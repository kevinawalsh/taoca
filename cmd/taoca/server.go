// Copyright (c) 2015, Kevin Walsh.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// https_ca_server acts as a CA to provide HTTPS/x509 certificates to Tao hosted
// programs. It can be run in two modes:
//
// * Manual (no policy)
//   In this mode, the private key for signing certificates is
//   password-protected. It relies on manual intervention to approve a
//   certificate signing request, presumably after some out-of-band screening
//   process has been completed. This is, in effect, what a real CA does. A
//   self-signed certificate for the signing key needs is also generated. This
//   needs to be installed into browsers manually. This mode need not run under
//   a Tao host, as it makes no use of Tao services.
//
// * Automated (with policy)
//   In this mode, we rely on the services of a Tao host to seal the private key
//   for signing certificates. The signing key is also bound to a specific
//   policy that dictates which certificate signing requests should be approved.
//   A (higher level, parent) CA is contacted to obtain a certificate for the
//   signing key. If the parent CA is trusted by browsers, then certificates
//   produced by the server in this mode will also be trusted by browsers.
//
//   Example Policy (using datalog guard) :
//     rule 0: forall P: forall OU: forall CN:
//         TrustedHttpsServerInstance(P, OU, CN)
//            implies Authorized(P, "ClaimCertificate", OU, CN)
//     rule 1: forall P: forall OU: forall CN: forall Hash:
//         TrustedHost(Host) and TrustedHttpsServer(Hash)
//            and Subprin(P, Host, Hash)
//            implies TrustedHttpsServerInstance(P, OU, CN)
//     rule 2: forall P: forall OU: forall CN: forall Hash:
//         TrustedHost(Host) and TrustedHttpsServer(Hash, OU, CN)
//            and Subprin(P, Host, Hash)
//            implies TrustedHttpsServerInstance(P, OU, CN)
//     rule 3: TrustedHttpsServer(ext.Program([....]))
//     rule 4: TrustedHttpsServer(ext.Program([....]))
//     rule 5: TrustedHttpsServer(ext.Program([....]), "CloudProxy Password Checker", "192.168.1.3")
//     rule 6: TrustedHttpsServer(ext.Program([....]), "CloudProxy Netlog Viewer", "192.168.1.4")
//   Here, rules 3-6 define programs that are trusted to act as http servers,
//   either with any name/addr, or with the specified name/addr. Rules 1 and 2
//   specify how those trusted servers can be instantiated, namely, by running
//   on a trusted host. Rule 0 specifies that only trusted instances can claim
//   certificates using the given x509 OrganizationalUnit and CommonName values.
//
// Requests:
//   CSR <name, is_ca, expiration, etc.>
// Responses:
//   OK <x509cert>
//   ERROR <msg>

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/jlmucb/cloudproxy/go/util/verbose"
	"github.com/kevinawalsh/profiling"
	"github.com/kevinawalsh/taoca"
	"github.com/kevinawalsh/taoca/netlog"
	"github.com/kevinawalsh/taoca/rendezvous"
)

var opts = []options.Option{
	// Flags for all commands
	{"host", "0.0.0.0", "<address>", "Address for listening", "all,persistent"},
	{"port", "8143", "<port>", "Port for listening", "all,persistent"},
	{"manual", false, "", "Require manual approval of requests", "all,persistent"},
	{"learn", false, "", "Auto-learn program hashes", "all,persistent"},
	{"init", false, "", "Initialize fresh signing keys", "all"},
	{"name", "https ca", "<name>", "Register with rendezvous using this name", "all,persistent"},
	{"root", false, "", "Act as a root CA, with a self-signed certificate", "all,persistent"},
	{"subsidiary", "", "<parentname>", "Act as a subsidiary CA, with a certificate signed by parent CA", "all,persistent"},
	{"pass", "", "<password>", "Signing key password for manual mode (for testing only!)", "all"},
	{"keys", "", "<dir>", "Directory for storing keys and associated certificates", "all,persistent"},
	{"docdir", "/etc/tao/https/docs/security/", "<dir>", "Directory for publishing CPS and unotice documents", "all,persistent"},
	{"docurl", "https://0.0.0.0:8443/security/", "<url>", "Base url at which published CPS and unotice documents are served", "all,persistent"},
	{"config", "/etc/tao/https_ca/ca.config", "<file>", "Location for storing configuration", "all"},
	{"stats", "", "", "rate to print status updates", "all,persistent"},
	{"profile", "", "", "filename to capture cpu profile", "all,persistent"},
}

var stats profiling.Stats

func init() {
	options.Add(opts...)
}

var caKeys *tao.Keys
var caRootName = &pkix.Name{
	Country:            []string{"US"},
	Province:           []string{"MA"},
	Locality:           []string{"Oakham"},
	Organization:       []string{"Google"},
	OrganizationalUnit: []string{"CloudProxy"},
	CommonName:         "Experimental Google CloudProxy HTTPS/TLS Root Certificate Authority",
}
var caSubsidiaryName = &pkix.Name{
	Country:            []string{"US"},
	Province:           []string{"MA"},
	Locality:           []string{"Oakham"},
	Organization:       []string{"Google"},
	OrganizationalUnit: []string{"CloudProxy"},
	CommonName:         "Experimental Google CloudProxy HTTPS/TLS Subsidiary Certificate Authority",
}

var manualMode bool
var policy tao.Guard

var learnMode bool
var knownHashes = make(map[string]bool)

var lock = &sync.RWMutex{}

func printRequest(req *taoca.Request, subjectKey *tao.Verifier, serial int64, peer string) {
	t := "Server (can't sign certificates)"
	if *req.CSR.IsCa {
		t = "Certificate Authority (can sign certificates)"
	}
	name := req.CSR.Name
	fmt.Printf("\n"+
		"A new Certificate Signing Request has been received:\n"+
		"  Country: %s\n"+
		"  Province: %s\n"+
		"  Locality: %s\n"+
		"  Organization: %s\n"+
		"  Organizational Unit: %s\n"+
		"  Common Name: %s\n"+
		"  Validity Period: %d years\n"+
		"  Type: %s\n"+
		"  Serial: %d\n"+
		"  Public Key Principal: %s\n"+
		"  Requesting Principal: %s\n"+
		"\n",
		*name.Country, *name.State, *name.City,
		*name.Organization, *name.OrganizationalUnit, *name.CommonName,
		*req.CSR.Years, t, serial, subjectKey.ToPrincipal(), peer)
}

func doError(ms util.MessageStream, err error, status taoca.ResponseStatus, detail string) {
	if err != nil {
		fmt.Printf("error handling request: %s\n", err)
	}
	fmt.Printf("sending error response: status=%s detail=%q\n", status, detail)
	resp := &taoca.Response{
		Status:      &status,
		ErrorDetail: proto.String(detail),
	}
	sendResponse(ms, resp)
}

func sendResponse(ms util.MessageStream, resp *taoca.Response) {
	_, err := ms.WriteMessage(resp)
	if err != nil {
		fmt.Printf("error writing response: %s\n", err)
	}
}

var legalChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890,:.()_/ "

func sanitize(s *string, fieldName string, errmsg *string) string {
	if *errmsg != "" {
		return ""
	}
	if s == nil {
		*errmsg = "missing name." + fieldName
		return ""
	}
	if *s == "" {
		*errmsg = "empty name." + fieldName
		return ""
	}
	for i := 0; i < len(*s); i++ {
		if !strings.ContainsRune(legalChars, rune((*s)[i])) {
			*errmsg = "invalid characters in name." + fieldName
			return ""
		}
	}
	if *s != strings.TrimSpace(*s) {
		*errmsg = "invalid whitespace in name." + fieldName
		return ""
	}
	return *s
}
func sanitizeURL(s *string, fieldName string, errmsg *string) string {
	// We only accept "http[s]://hostname/path..."
	// though path can be empty.
	url := sanitize(s, fieldName, errmsg)
	if *errmsg != "" {
		return url
	}
	url = strings.TrimRight(url, "/")
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return url
	} else {
		*errmsg = "invalid URL prefix"
		return ""
	}
}

func publish(doc []byte) (url string, err error) {
	docurl := *options.String["docurl"]
	docdir := *options.String["docdir"]

	h := sha256.Sum256(doc)
	p := path.Join(docdir, fmt.Sprintf("%x.txt", h))
	err = util.WritePath(p, doc, 0777, 0666)
	if err != nil {
		return
	}

	if !strings.HasSuffix(docurl, "/") {
		docurl += "/"
	}
	url = fmt.Sprintf("%s%x.txt", docurl, h)
	return
}

func doResponseWithStats(conn *tao.Conn) {
	op := profiling.NewOp()
	ok := doResponse(conn)
	stats.Done(&op, ok)
}

func doResponseWithoutStats(conn *tao.Conn) {
	verbose.Println("Processing request")
	doResponse(conn)
}

// NewX509Name returns a new pkix.Name.
func NewX509Name(p *taoca.X509Details) *pkix.Name {
	return &pkix.Name{
		Country:            []string{p.GetCountry()},
		Organization:       []string{p.GetOrganization()},
		OrganizationalUnit: []string{p.GetOrganizationalUnit()},
		Province:           []string{p.GetState()},
		Locality:           []string{p.GetCity()},
		CommonName:         string(p.GetCommonName()),
	}
}

func doResponse(conn *tao.Conn) bool {
	// conn.Trace = tao.NewTrace(6, 1)
	T := profiling.NewTrace(10, 1)
	T.Start()
	defer conn.Close()

	var req taoca.Request

	if err := conn.ReadMessage(&req); err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "failed to read request")
		return false
	}
	T.Sample("got msg") // 1

	peer := "anonymous"
	if conn.Peer() != nil {
		peer = conn.Peer().String()
	}
	T.Sample("got peer") // 2

	var errmsg string

	// Check whether the CSR is well-formed
	name := req.CSR.Name
	sanitize(name.Country, "Country", &errmsg)
	sanitize(name.State, "State/Province", &errmsg)
	sanitize(name.City, "City/Locality", &errmsg)
	sanitize(name.Organization, "Organization", &errmsg)
	ou := sanitize(name.OrganizationalUnit, "OrganizationalUnit", &errmsg)
	cn := sanitize(name.CommonName, "CommonName", &errmsg)
	years := *req.CSR.Years
	if years <= 0 {
		errmsg = "invalid validity period"
	}
	if errmsg != "" {
		doError(conn, nil, taoca.ResponseStatus_TAOCA_BAD_REQUEST, errmsg)
		return false
	}
	T.Sample("sanitized") // 3

	var ck tao.CryptoKey
	if err := proto.Unmarshal(req.CSR.PublicKey, &ck); err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "can't unmarshal key")
		return false
	}
	subjectKey, err := tao.UnmarshalVerifierProto(&ck)
	if err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "can't unmarshal key")
		return false
	}
	T.Sample("got subject") // 4

	// TODO(kwalsh) more robust generation of serial numbers?
	var serial int64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &serial); err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_ERROR, "could not generate random serial number")
	}
	if serial < 0 {
		serial = ^serial
	}
	T.Sample("made serial") // 5

	if verbose.Enabled {
		printRequest(&req, subjectKey, serial, peer)
	}

	var cps, unotice string
	if manualMode {
		lock.Lock()
		var ok string
		for {
			ok = options.Confirm("Approve this request?", "no")
			if ok == "yes" || ok == "no" {
				break
			}
			fmt.Printf("I don't understand %q. Please type yes or no.\n", ok)
		}
		lock.Unlock()

		if ok != "yes" {
			doError(conn, nil, taoca.ResponseStatus_TAOCA_REQUEST_DENIED, "request is denied")
			return false
		}

		fmt.Printf("Issuing certificate.\n")

		cps = cpsTemplate + cpsManual
	} else {
		// Consult guard to enforce policy.
		if conn.Peer() == nil {
			doError(conn, nil, taoca.ResponseStatus_TAOCA_REQUEST_DENIED, "anonymous request is denied")
			return false
		}

		if learnMode {
			prin := *conn.Peer()
			if len(prin.Ext) > 0 {
				last := prin.Ext[len(prin.Ext)-1]
				tail := auth.PrinTail{
					Ext: auth.SubPrin([]auth.PrinExt{last}),
				}
				prinHash := fmt.Sprintf("Known(%v)", tail)
				if !knownHashes[prinHash] {
					fmt.Printf("Learned: %s\n", prinHash)
					knownHashes[prinHash] = true
					if err := policy.AddRule(prinHash); err != nil {
						fmt.Println("Error adding rule: %s\n", err)
					}
				}
			}
		}

		if !policy.IsAuthorized(*conn.Peer(), "ClaimCertificate", []string{*name.OrganizationalUnit, *name.CommonName}) &&
			!policy.IsAuthorized(*conn.Peer(), "ClaimCertificate", nil) {
			fmt.Printf("Policy (as follows) does not allow this request\n")
			fmt.Printf("%s\n", policy.String())
			doError(conn, nil, taoca.ResponseStatus_TAOCA_REQUEST_DENIED, "request is denied")
			return false
		}

		if _, ok := policy.(*tao.ACLGuard); ok {
			cps = cpsTemplate + cpsACL
		} else {
			cps = cpsTemplate + cpsDatalog
		}
		cps += "\n" + policy.String()
	}
	T.Sample("authenticated") // 6

	if conn.Peer() != nil {
		unotice = fmt.Sprintf(unoticeTemplate+
			"* The certificate was requested by the following Tao principal:\n\n   %v\n",
			*conn.Peer())
	} else {
		unotice = fmt.Sprintf(unoticeTemplate +
			"* The certificate was requested anonymously.\n")
	}
	cpsUrl, err := publish([]byte(cps))
	unoticeUrl, err := publish([]byte(unotice))

	// ext, err := taoca.NewUserNotice("Hello user, how are you?")
	ext, err := taoca.NewCertficationPolicy(cpsUrl, unoticeUrl)
	if err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_ERROR, "failed to generate certificate policy extension")
		return false
	}
	T.Sample("made cps") // 7

	netlog.Log("https_ca: issuing certificate for ou=%q cn=%q to %s", ou, cn, peer)

	template := caKeys.SigningKey.X509Template(NewX509Name(name), ext)
	template.IsCA = *req.CSR.IsCa
	template.SerialNumber.SetInt64(serial)
	cert, err := caKeys.CreateSignedX509(subjectKey, template, "default")
	if err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_ERROR, "failed to generate certificate")
		return false
	}
	T.Sample("signed cert") // 8

	status := taoca.ResponseStatus_TAOCA_OK
	resp := &taoca.Response{
		Status: &status,
		Cert:   []*taoca.Cert{&taoca.Cert{X509Cert: cert.Raw}},
	}
	for _, parent := range caKeys.CertChain("default") {
		resp.Cert = append(resp.Cert, &taoca.Cert{X509Cert: parent.Raw})
	}
	T.Sample("built response") // 9

	sendResponse(conn, resp)
	T.Sample("sent response") // 10
	//fmt.Println(T)
	return true
}

func main() {
	verbose.Set(true)
	options.Parse()

	profiling.ProfilePath = *options.String["profile"]

	if !verbose.Enabled {
		taoca.ConfirmNames = false
	}

	if *options.String["config"] != "" && !*options.Bool["init"] {
		err := options.Load(*options.String["config"])
		options.FailIf(err, "Can't load configuration")
	}

	fmt.Println("https/tls Certificate Authority")

	manualMode = *options.Bool["manual"]
	learnMode = *options.Bool["learn"]

	if !manualMode && tao.Parent() == nil {
		options.Fail(nil, "can't continue: automatic mode, but no host Tao available")
	}

	if *options.Bool["root"] == (*options.String["subsidiary"] != "") {
		options.Usage("must supply exactly one of -root or -subsidiary options")
	}

	host := *options.String["host"]
	port := *options.String["port"]
	addr := net.JoinHostPort(host, port)

	// TODO(kwalsh) extend tao name with operating mode and policy

	cpath := *options.String["config"]
	kdir := *options.String["keys"]
	if kdir == "" && cpath != "" {
		kdir = path.Dir(cpath)
	} else if kdir == "" {
		options.Fail(nil, "Option -keys or -config is required")
	}
	ppath := path.Join(kdir, "policy")

	var err error

	if *options.Bool["init"] {
		if cpath != "" {
			err := options.Save(cpath, "HTTPS/TLS certificate authority configuration", "persistent")
			options.FailIf(err, "Can't save configuration")
		}
		fmt.Println("" +
			"Initializing fresh HTTP/TLS CA signing key. Provide the following information,\n" +
			"to be include in the CA's own x509 certificate. Leave the response blank to\n" +
			"accept the default value.\n" +
			"\n" +
			"Configuration file: " + cpath + "\n" +
			"Keys directory: " + kdir + "\n")

		var caName *pkix.Name
		if taoca.ConfirmNames {
			if *options.Bool["root"] {
				caName = taoca.ConfirmName(caRootName)
			} else {
				caName = taoca.ConfirmName(caSubsidiaryName)
			}
		} else {
			if *options.Bool["root"] {
				caName = caRootName
			} else {
				caName = caSubsidiaryName
			}
		}

		if manualMode {
			pwd := options.Password("Choose an HTTPS/TLS CA signing key password", "pass")
			caKeys, err = tao.InitOnDiskPBEKeys(tao.Signing, pwd, kdir, caName)
			tao.ZeroBytes(pwd)
		} else {
			caKeys, err = tao.InitOnDiskTaoSealedKeys(tao.Signing, caName, tao.Parent(), kdir, tao.SealPolicyDefault)
		}
		options.FailIf(err, "Can't initialize fresh HTTPS/TLS CA signing key")
		if *options.Bool["root"] {
			fmt.Printf(""+
				"Note: To install this CA's key in the Chrome browser, go to\n"+
				"  'Settings', 'Show advanced settings...', 'Manage Certificates...', 'Authorities'\n"+
				"  then import the following file:\n"+
				"     %s\n"+
				"  Select 'Trust this certificate for identifying websites' and/or other\n"+
				"  options, then click 'OK'\n", caKeys.X509Path("default"))
		} else {
			csr := taoca.NewCertificateSigningRequest(caKeys.VerifyingKey, caName)
			*csr.IsCa = true
			srv := *options.String["subsidiary"]
			taoca.DefaultServerName = srv
			taoca.SubmitAndInstall(caKeys, csr)
		}

		if !manualMode {
			f, err := os.Open(ppath)
			if err == nil {
				f.Close()
				fmt.Printf("Using existing certificate-granting policy: %s\n", ppath)
			} else {
				fmt.Printf("Creating default certificate-granting policy: %s\n", ppath)
				fmt.Printf("Edit that file to define the certificate-granting policy.\n")
				err := util.WritePath(ppath, []byte(defPolicy), 0755, 0755)
				options.FailIf(err, "Can't save policy rules")
			}
		}
	} else {
		if manualMode {
			pwd := options.Password("HTTPS/TLS CA signing key password", "pass")
			caKeys, err = tao.LoadOnDiskPBEKeys(tao.Signing, pwd, kdir)
			tao.ZeroBytes(pwd)
		} else {
			caKeys, err = tao.LoadOnDiskTaoSealedKeys(tao.Signing, tao.Parent(), kdir, tao.SealPolicyDefault)
		}
		options.FailIf(err, "Can't load HTTP/TLS CA signing key")
	}

	netlog.Log("https_ca: start")
	netlog.Log("https_ca: manual? %v", manualMode)

	if !manualMode {
		policy, err = LoadPolicy(ppath)
		options.FailIf(err, "Can't load certificate-granting policy")
	}

	var prin auth.Prin
	if tao.Parent() != nil {
		prin, err = tao.Parent().GetTaoName()
		options.FailIf(err, "Can't get tao name")
	} else {
		rendezvous.DefaultServer.Connect(caKeys)
		prin = caKeys.SigningKey.ToPrincipal()
	}

	name := *options.String["name"]
	if name != "" {
		err = rendezvous.Register(rendezvous.Binding{
			Name:      proto.String(name),
			Host:      proto.String(host),
			Port:      proto.String(port),
			Protocol:  proto.String("protoc/rpc/https_ca"),
			Principal: proto.String(prin.String()),
		})
		options.FailIf(err, "Can't register with rendezvous service")
	}

	statsdelay := *options.String["stats"]
	var srv *tao.Server
	if statsdelay != "" {
		go profiling.ShowStats(&stats, statsdelay, "sign certificates")
		srv = tao.NewOpenServer(tao.ConnHandlerFunc(doResponseWithStats))
	} else {
		srv = tao.NewOpenServer(tao.ConnHandlerFunc(doResponseWithoutStats))
	}

	srv.Keys = caKeys
	fmt.Printf("Listening at %s using Tao-authenticated channels\n", addr)
	err = srv.ListenAndServe(addr)
	options.FailIf(err, "server died")

	fmt.Println("Server Done")
	netlog.Log("https_ca: done")
}

// There is room for two two URLs in each issued certificate. The first, the CPS
// or Certification Practices Statement, links to a statement of the approval
// practices under which this CA is operating. The second links to a User Notice
// statement about this specific certificate request, containing e.g. the full,
// verified Tao principal name of the subject. The integrity of these documents
// matters, so we hash them and embed the hash in the URL.

var cpsTemplate = `Experimental Cloudproxy HTTPS Certificate Authority
** Certification Practices Statement **

This document specifies the practices and policies under which certificate
signing requests are approved by some instance of the Experimental Cloudproxy
HTTPS Certificate Authority.

Document Integrity
------------------

This document should be hosted as a file with name <hhh>.txt where <hhh> is the
sha256 hash of this document. If the document hash does not match the file name,
then the contents of this document should not be trusted.

Policies
--------

* Certificates issued will include extended validation (EV) information,
  including links to this document and a user notice document under the
  id-qt-cps and id-qt-unotice extensions. The user notice document will include
  details about the circumstances under which the certificate was issued.
`

var cpsManual = `
* Certificate signing requests are vetted and approved manually by the holder of
  the certficiate authority private signing key.
`

var cpsACL = `
* Certificate signing requests are approved automatically to principals
  as described in the following access-control list:
`

var cpsDatalog = `
* Certificate signing requests are approved automatically to principals
  as described by to the following datalog rules:
`
var unoticeTemplate = `Experimental Cloudproxy HTTPS Certificate Authority
** User Notice **

This document details the circumstances under which some certificate was issued
by some instance of the Experimental Cloudproxy HTTPS Certificate Authority.

Document Integrity
------------------

This document should be hosted as a file with name <hhh>.txt where <hhh> is the
sha256 hash of this document. If the document hash does not match the file name,
then the contents of this document should not be trusted.

Issuance Details
----------------

`
