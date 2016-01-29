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

package x509txt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/kevinawalsh/taoca/util/indent"
)

func String(cert *x509.Certificate) string {
	var b bytes.Buffer
	Dump(indent.NewTextWriter(&b, 80), cert)
	return b.String()
}

func Html(cert *x509.Certificate) string {
	var b bytes.Buffer
	Dump(indent.NewHtmlWriter(&b), cert)
	return b.String()
}

func Dump(w indent.Writer, cert *x509.Certificate) {
	w.Headerf("Certificate:\n")

	w.Printf("Version: %s\n", w.Bold("%v", cert.Version))
	w.Printf("Serial Number: %s\n", w.Bold("%v (0x%x)\n", cert.SerialNumber, cert.SerialNumber))
	w.Printf("Issuer: %s\n", w.Bold("%s", RDNString(cert.Issuer)))

	w.Headerf("Validity:\n")
	w.Printf("Not Before: %s\n", w.Bold("%v", cert.NotBefore))
	w.Printf("Not After : %s\n", w.Bold("%v", cert.NotAfter))
	w.Dedent()

	w.Printf("Subject: %s\n", w.Bold(RDNString(cert.Subject)))
	w.Headerf("Subject Public Key Info:\n")
	pubkeyDump(w, cert)
	w.Dedent()

	w.Headerf("X509v3 Extensions:\n")
	if cert.KeyUsage != 0 {
		s := []string{}
		for t, d := range X509KeyUsage {
			if cert.KeyUsage&t != 0 {
				s = append(s, d)
			}
		}
		w.Headerf("X509v3 Key Usage:\n")
		w.Println(w.Bold("%s", strings.Join(s, ", ")))
		w.Dedent()
	}
	if cert.KeyUsage != 0 {
		s := []string{}
		for _, u := range cert.ExtKeyUsage {
			s = append(s, X509ExtKeyUsage[u])
		}
		w.Headerf("X509v3 Extended Key Usage:\n")
		w.Println(w.Bold("%s", strings.Join(s, ", ")))
		w.Dedent()
	}
	if cert.BasicConstraintsValid {
		w.Headerf("X509v3 Basic Constraints:\n")
		w.Printf("CA: %s\n", w.Bold("%v", cert.IsCA))
		if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
			w.Printf("MaxPathLen: %s\n", w.Bold("%v", cert.MaxPathLen))
		}
		w.Dedent()
	}
	for _, e := range cert.Extensions {
		if cps, unotice, err := ExtractCertificationPolicy(e); err == nil {
			w.Headerf("Policy:\n")
			w.Printf("CPS: %s\n", w.Link(cps, w.Bold(cps)))
			w.Printf("User Notice: %s\n", w.Link(unotice, w.Bold(unotice)))
			w.Dedent()
		}
	}
	w.Dedent()

	w.Headerf("Signature Algorithm: %s\n", w.Bold("%v", SigAlgName[cert.SignatureAlgorithm]))
	w.PrintHex(cert.Signature)
	w.Dedent()

	w.Dedent()
}

/*
func X509Dump(w io.Writer, cert *x509.Certificate, func bold(s string) string) {
	w =
	w.Printf("<h2>Certificate:</h2><ul>\n")
	w.Printf(" <li>Version: <b>%d</b></li>\n", cert.Version)
	w.Printf(" <li>Serial Number: <b>%v</b> (<b>0x%x</b>)</li>\n", cert.SerialNumber, cert.SerialNumber)
	w.Printf(" <li>Issuer: <b>%s</b></li>\n", RDNString(cert.Issuer))
	w.Printf(" <li>Validity:<ul>\n")
	w.Printf("   <li>Not Before: <b>%v</b></li>\n", cert.NotBefore)
	w.Printf("   <li>Not After: <b>%v</b></li>\n", cert.NotAfter)
	w.Printf(" </ul></li>\n")
	w.Printf(" <li>Subject: <b>%s</b></li>\n", RDNString(cert.Subject))
	w.Printf(" <li>Subject Public Key Info:<ul>\n")
	pubkeyDump(w, cert)
	w.Printf("    X509v3 extensions:\n")
	if cert.KeyUsage != 0 {
		s := []string{}
		for t, d := range X509KeyUsage {
			if cert.KeyUsage&t != 0 {
				s = append(s, d)
			}
		}
		w.Printf("      X509v3 Key Usage:\n")
		w.Printf("        %s\n", strings.Join(s, ", "))
	}
	if cert.KeyUsage != 0 {
		s := []string{}
		for _, u := range cert.ExtKeyUsage {
			s = append(s, x509ExtKeyUsage[u])
		}
		w.Printf("      X509v3 Extended Key Usage:\n")
		w.Printf("        %s\n", strings.Join(s, ", "))
	}
	if cert.BasicConstraintsValid {
		w.Printf("      X509v3 Basic Constraints:\n")
		w.Printf("        CA: %v\n", cert.IsCA)
		if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
			w.Printf("        MaxPathLen: %d\n", cert.MaxPathLen)
		}
	}
	w.Printf("    Signature Algorithm: %v\n", SigAlgName[cert.SignatureAlgorithm])
	HexDump(w, 80, "      ", cert.Signature)
	w.Printf("</ul>")
}
*/

var X509KeyUsage = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "Digital Signature",
	x509.KeyUsageContentCommitment: "Content Commitment",
	x509.KeyUsageKeyEncipherment:   "Key Encipherment",
	x509.KeyUsageDataEncipherment:  "Data Encipherment",
	x509.KeyUsageKeyAgreement:      "Key Agreement",
	x509.KeyUsageCertSign:          "Certificate Sign",
	x509.KeyUsageCRLSign:           "CRL Sign",
	x509.KeyUsageEncipherOnly:      "Encipher Only",
	x509.KeyUsageDecipherOnly:      "Decipher Only",
}

var X509ExtKeyUsage = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "Any",
	x509.ExtKeyUsageServerAuth:                 "TLS Web Server Authentication",
	x509.ExtKeyUsageClientAuth:                 "TLS Web Client Authentication",
	x509.ExtKeyUsageCodeSigning:                "Code Signing",
	x509.ExtKeyUsageEmailProtection:            "Email Protection",
	x509.ExtKeyUsageIPSECEndSystem:             "IPSEC End System",
	x509.ExtKeyUsageIPSECTunnel:                "IPSEC Tunnel",
	x509.ExtKeyUsageIPSECUser:                  "IPSEC User",
	x509.ExtKeyUsageTimeStamping:               "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "Netscape Server Gated Crypto",
}

var SigAlgName = map[x509.SignatureAlgorithm]string{
	x509.UnknownSignatureAlgorithm: "Unknown",
	x509.MD2WithRSA:                "MD2WithRSA",
	x509.MD5WithRSA:                "MD5WithRSA",
	x509.SHA1WithRSA:               "SHA1WithRSA",
	x509.SHA256WithRSA:             "SHA256WithRSA",
	x509.SHA384WithRSA:             "SHA384WithRSA",
	x509.SHA512WithRSA:             "SHA512WithRSA",
	x509.DSAWithSHA1:               "DSAWithSHA1",
	x509.DSAWithSHA256:             "DSAWithSHA256",
	x509.ECDSAWithSHA1:             "ECDSAWithSHA1",
	x509.ECDSAWithSHA256:           "ECDSAWithSHA256",
	x509.ECDSAWithSHA384:           "ECDSAWithSHA384",
	x509.ECDSAWithSHA512:           "ECDSAWithSHA512",
}

var EcdsaCurveName = map[elliptic.Curve]string{
	elliptic.P224(): "P-224",
	elliptic.P256(): "P-256",
	elliptic.P384(): "P-384",
	elliptic.P521(): "P-521",
}

func pubkeyDump(w indent.Writer, cert *x509.Certificate) {
	switch cert.PublicKeyAlgorithm {
	case x509.ECDSA:
		w.Printf("Public Key Algorithm: %s\n", w.Bold("ECDSA"))
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			w.Println(w.Bold("[unrecognizable]"))
			return
		}
		w.Headerf("Public Key: (%s)\n", w.Bold("%d bits", pub.Params().BitSize))
		w.PrintHex(elliptic.Marshal(pub.Curve, pub.X, pub.Y))
		w.Dedent()
		w.Printf("Curve: %s\n", EcdsaCurveName[pub.Curve])
		return
	case x509.RSA:
		w.Printf("Public Key Algorithm: RSA\n")
	case x509.DSA:
		w.Printf("Public Key Algorithm: DSA\n")
	default:
		w.Printf("Public Key Algorithm: Unknown (type %d)\n", cert.PublicKeyAlgorithm)
	}
	b, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	w.Headerf("Public Key:\n")
	if err != nil {
		w.Printf("[unrecognizable]\n")
	} else {
		w.PrintHex(b)
	}
	w.Dedent()
}

// RDNString formats an x509 name in a familiar notation like "C=US, O=Google,
// OU=Cloudproxy", more or less according to rfc 4514. Note that pkix.Name does
// not appear to preserve the structure of multi-valued RDNs, so '+' is not used
// the encoding. Non-standard RDN types are ignored.
func RDNString(n pkix.Name) string {
	// Shorthand for PostalCode and SerialNumber does not seem to be defined,
	// so we use ZIP and SERIAL.
	types := []string{"C", "O", "OU", "L", "ST", "STREET", "ZIP", "SERIAL", "CN"}
	vals := [][]string{
		n.Country, n.Organization, n.OrganizationalUnit,
		n.Locality, n.Province, n.StreetAddress, n.PostalCode,
	}
	if len(n.SerialNumber) > 0 {
		vals = append(vals, []string{n.SerialNumber})
	} else {
		vals = append(vals, []string{})
	}
	if len(n.CommonName) > 0 {
		vals = append(vals, []string{n.CommonName})
	} else {
		vals = append(vals, []string{})
	}
	var w bytes.Buffer
	sep := ""
	for i, t := range types {
		for _, v := range vals[i] {
			fmt.Fprintf(&w, "%s%s=%s", sep, t, RDNEscape(v))
			sep = ", "
		}
	}
	return w.String()
}

// RDNEscape adds escapes suitable for the string encoding of a an RDN value.
func RDNEscape(s string) string {
	var w bytes.Buffer
	for i := 0; i < len(s); i++ {
		r := rune(s[i])
		switch r {
		case ' ':
			if i == 0 || i == len(s)-1 {
				w.WriteRune('\\')
			}
			w.WriteRune(r)
		case '#':
			if i == 0 {
				w.WriteRune('\\')
			}
			w.WriteRune(r)
		case '"', '+', ',', ';', '<', '=', '>', '\\':
			// Note: escaping '=' is optional but seems sensible.
			w.WriteRune('\\')
			w.WriteRune(r)
		case '\x00':
			w.WriteString(`\00`)
		default:
			w.WriteRune(r)
		}
	}
	return w.String()
}

// For unknown reasons, Chrome and openssl insist on different encodings for the
// two qualifiers. For CPS, the qualifier is an IA5string sibling to the OID.
// For UserNotice, the qualifier must be embeded as a VisibleString inside a
// sequence (of length 1) that is a sibling to the OID.

type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
	PolicyQualifiers []byte
}

type policyQualifierInfo struct {
	PolicyQualifierId asn1.ObjectIdentifier
	Qualifier         string `asn1:"tag:optional,ia5"`
}

type policyQualifierInfoSequence struct {
	PolicyQualifierId asn1.ObjectIdentifier
	// asn1.Marshal does not support VisibleString encoding. As a workaround, encode
	// as PrintableString, then change the tag after encoding. See NewCertificationPolicy.
	Qualifier []string
}

var (
	// joint-iso-itu-t(2) ds(5) certificateExtension(29) certificatePolicies(32)
	idCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}

	// iso(1) identified-organization(3) dod(6) internet(1) security(5)
	//   mechanisms(5) pkix(7) id-qt(2) id-qt-cps(1)
	idQtCertificationPracticeStatement = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}

	// iso(1) identified-organization(3) dod(6) internet(1) security(5)
	//   mechanisms(5) pkix(7) id-qt(2) id-qt-unotice(2)
	idQtUnotice = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}

	// joint-iso-itu-t(2) international-organizations(23) ca-browser-forum(140)
	//   certificate-policies(1) baseline-requirements(2) subject-identity-validated(2)
	idSubjectIdentityValidated = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 2}

	asn1PrintableStringTag byte = 19
	asn1VisibleStringTag   byte = 26
)

func ExtractCertificationPolicy(e pkix.Extension) (cps, unotice string, err error) {
	if !e.Id.Equal(idCertificatePolicies) {
		return "", "", fmt.Errorf("ASN OID mismatch")
	}
	var pi []struct {
		Id               asn1.ObjectIdentifier
		PolicyQualifiers []struct {
			Id    asn1.ObjectIdentifier
			Value asn1.RawValue
		}
	}
	rest, err := asn1.Unmarshal(e.Value, &pi)
	if err != nil {
		return "", "", err
	}
	if len(rest) > 0 {
		return "", "", fmt.Errorf("Trailing data after x509 Policy extension: % 02x", rest)
	}
	if len(pi) != 1 {
		return "", "", fmt.Errorf("Unexpected count for x509 Policy extension: %d", len(pi))
	}
	if !pi[0].Id.Equal(idSubjectIdentityValidated) {
		return "", "", fmt.Errorf("Unrecognized OID for x509 Policy extension: %v", pi[0].Id)
	}
	q := pi[0].PolicyQualifiers
	if len(q) != 2 {
		return "", "", fmt.Errorf("Unexpected count for x509 Policy extension qualifiers: %d", len(pi[0].PolicyQualifiers))
	}
	if !q[0].Id.Equal(idQtCertificationPracticeStatement) {
		return "", "", fmt.Errorf("Unrecognized OID for x509 Policy extension CPS: %v", q[0].Id)
	}
	rest, err = asn1.Unmarshal(q[0].Value.FullBytes, &cps)
	if err != nil {
		return "", "", fmt.Errorf("Error extracting CPS: %v", err)
	}
	if len(rest) > 0 {
		return "", "", fmt.Errorf("Trailing data after x509 Policy extension CPS: % 02x", rest)
	}
	if !q[1].Id.Equal(idQtUnotice) {
		return "", "", fmt.Errorf("Unrecognized OID for x509 Policy extension User Notice: %v", q[1].Id)
	}
	if len(q[1].Value.Bytes) > 0 && q[1].Value.Bytes[0] == asn1VisibleStringTag {
		q[1].Value.Bytes[0] = asn1PrintableStringTag
	}
	rest, err = asn1.Unmarshal(q[1].Value.Bytes, &unotice)
	if err != nil {
		return "", "", fmt.Errorf("Error extracting user notice: %v", err)
	}
	if len(rest) > 0 {
		return "", "", fmt.Errorf("Trailing data after x509 Policy extension User Notice: % 02x", rest)
	}
	return cps, unotice, nil
}
