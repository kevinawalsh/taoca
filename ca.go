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

package taoca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/jlmucb/cloudproxy/go/util/verbose"
	"github.com/kevinawalsh/taoca/rendezvous"
	"github.com/kevinawalsh/taoca/util/x509txt"
)

// Server holds parameters for connecting to a TaoCA server.
type Server struct {
	Host, Port string
}

// NewCertificateSigningRequest initializes a new CSR with the given key and
// name, a default parameters for other fields.
func NewCertificateSigningRequest(key *tao.Verifier, name *pkix.Name) *CSR {
	keydata, _ := proto.Marshal(tao.MarshalVerifierProto(key))
	return &CSR{
		PublicKey: keydata,
		Name: &X509Details{
			CommonName:         proto.String(name.CommonName),
			Country:            proto.String(name.Country[0]),
			State:              proto.String(name.Province[0]),
			City:               proto.String(name.Locality[0]),
			Organization:       proto.String(name.Organization[0]),
			OrganizationalUnit: proto.String(name.OrganizationalUnit[0]),
		},
		Years: proto.Int32(1),
		IsCa:  proto.Bool(false),
	}
}

var DefaultServerName = "https ca"
var Warn = true
var DefaultServer *Server
var defaultServerErr error
var once sync.Once

// Submit sends a CSR to the default certificate authority server, which is
// located using rendezvous lookup for "https ca". The keys are used to
// authenticate to the server.
func GetDefaultServer() (*Server, error) {
	once.Do(func() {
		if DefaultServer != nil {
			return
		}
		b, err := rendezvous.Lookup(DefaultServerName)
		if err != nil {
			defaultServerErr = err
			return
		}
		if len(b) == 0 {
			defaultServerErr = fmt.Errorf("no https certificate authority servers found")
			return
		}
		DefaultServer = &Server{
			Host: *b[0].Host,
			Port: *b[0].Port,
		}
	})
	return DefaultServer, defaultServerErr
}

// Submit sends a CSR to the default certificate authority server, which is
// located using rendezvous lookup for "https ca". The keys are used to
// authenticate to the server.
func Submit(keys *tao.Keys, csr *CSR) ([]*x509.Certificate, error) {
	server, err := GetDefaultServer()
	if err != nil {
		return nil, err
	}
	return server.Submit(keys, csr)
}

// Submit sends a CSR to a certificate authority server. The keys are used to
// authenticate to the server.
func (server *Server) Submit(keys *tao.Keys, csr *CSR) ([]*x509.Certificate, error) {
	addr := net.JoinHostPort(server.Host, server.Port)
	conn, err := tao.Dial("tcp", addr, nil /* guard */, nil /* verifier */, keys, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ms := util.NewMessageStream(conn)

	req := &Request{CSR: csr}
	_, err = ms.WriteMessage(req)
	if err != nil {
		return nil, err
	}

	var resp Response
	if err := ms.ReadMessage(&resp); err != nil {
		return nil, err
	}
	if *resp.Status != ResponseStatus_TAOCA_OK {
		detail := "unknown error"
		if resp.ErrorDetail != nil {
			detail = *resp.ErrorDetail
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, detail)
	}
	if len(resp.Cert) == 0 {
		return nil, fmt.Errorf("no certificates in CA response")
	}
	certs := make([]*x509.Certificate, len(resp.Cert))
	for i, c := range resp.Cert {
		cert, err := x509.ParseCertificate(c.X509Cert)
		if err != nil {
			return nil, err
		}
		certs[i] = cert
	}
	return certs, nil
}

func ConfirmName(n *pkix.Name) *pkix.Name {
	return &pkix.Name{
		Country:            options.ConfirmN("Country", n.Country),
		Province:           options.ConfirmN("State or Province Name", n.Province),
		Locality:           options.ConfirmN("City or Locality Name", n.Locality),
		Organization:       options.ConfirmN("Organization Name (e.g. company)", n.Organization),
		OrganizationalUnit: options.ConfirmN("Organization UnitName (e.g. section)", n.OrganizationalUnit),
		CommonName:         options.Confirm("Common Name", n.CommonName),
	}
}

var ConfirmNames = true

// GenerateKeys initializes a new tls key, confirms certificate details with the
// user, obtains a signed certificate from the default ca, and stores the
// resulting keys and certificates in kdir. This is meant to be called from
// user-facing apps.
func GenerateKeys(name *pkix.Name, addr, kdir string) *tao.Keys {
	host, _, err := net.SplitHostPort(addr)
	options.FailIf(err, "bad address: %s", addr)
	name.CommonName = host

	if ConfirmNames {
		fmt.Printf(""+
			"Initializing fresh HTTP/TLS server key. Provide the following information,\n"+
			"to be include in a CA-signed x509 certificate. Leave the response blank to\n"+
			"accept the default value.\n\n"+
			"The key and certificates will be stored in:\n  %s\n\n", kdir)
		name = ConfirmName(name)
	}

	keys, err := tao.InitOnDiskTaoSealedKeys(tao.Signing, name, tao.Parent(), kdir, tao.SealPolicyDefault)
	options.FailIf(err, "can't create tao-sealed HTTPS/TLS keys")

	csr := NewCertificateSigningRequest(keys.VerifyingKey, name)

	SubmitAndInstall(keys, csr)
	return keys
}

func SubmitAndInstall(keys *tao.Keys, csr *CSR) {
	verbose.Printf("Obtaining certificate from CA (may take a while)\n")
	resp, err := Submit(keys, csr)
	options.FailIf(err, "can't obtain X509 certificate from CA")
	if len(resp) == 0 {
		options.Fail(nil, "no x509 certificates returned from CA")
	}
	// Add the certs to our keys...
	keys.Cert["default"] = resp[0]
	for i, c := range resp {
		name := "ca"
		if i > 0 {
			name = fmt.Sprintf("ca-%d", i)
		}
		keys.Cert[name] = c
	}
	if keys.X509Path("default") != "" {
		err = keys.SaveCerts()
	}
	options.FailIf(err, "can't save X509 certificates")

	chain := keys.CertChain("default")
	verbose.Printf("Obtained certfificate chain of length %d:\n", len(chain))
	for i, cert := range chain {
		verbose.Printf("  Cert[%d] Subject: %s\n", i, x509txt.RDNString(cert.Subject))
	}
	if Warn {
		fmt.Println("Note: You may need to install root CA's key into the browser.")
	}
}

// LoadKeys loads and https key and cert from a directory. This is meant to be
// called from user-facing apps.
func LoadKeys(kdir string) *tao.Keys {
	// TODO(kwalsh) merge x509 load/save code into keys.go
	keys, err := tao.LoadOnDiskTaoSealedKeys(tao.Signing, tao.Parent(), kdir, tao.SealPolicyDefault)
	options.FailIf(err, "can't load tao-sealed HTTPS/TLS keys")

	chain := keys.CertChain("default")
	verbose.Printf("Using existing certfificate chain of length %d:\n", len(chain))
	for i, cert := range chain {
		verbose.Printf("  Cert[%d] Subject: %s\n", i, x509txt.RDNString(cert.Subject))
	}

	return keys
}
