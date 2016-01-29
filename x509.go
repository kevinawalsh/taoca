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

// The code in this file is based on
//   https://github.com/jsha/cfssl/commit/ae0c2c17c6f24f6e31483136440be82c3444a50d
// which was accompanied by the following license text:
//
// Copyright (c) 2014 CloudFlare Inc.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package taoca

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// For unknown reasons, Chrome and openssl insist on different encodings for the
// two qualifiers. For CPS, the qualifier is an IA5string sibling to the OID.
// For UserNotice, the qualifier must be embeded as a VisibleString inside a
// sequence (of length 1) that is a sibling to the OID.

type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
	PolicyQualifiers []interface{} `asn1:"omitempty"`
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

// NewCertficationPolicy creates an x509 certificate extension detailing a
// certification policy, including a statement and a user notice. The resulting
// extension can be added to x509.Certficate.ExtraExtensions.
func NewCertficationPolicy(cps, unotice string) (pkix.Extension, error) {
	pi := []policyInformation{
		policyInformation{
			PolicyIdentifier: idSubjectIdentityValidated,
			PolicyQualifiers: []interface{}{
				policyQualifierInfo{
					PolicyQualifierId: idQtCertificationPracticeStatement,
					Qualifier:         cps,
				},
				policyQualifierInfoSequence{
					PolicyQualifierId: idQtUnotice,
					Qualifier:         []string{unotice},
				},
			},
		},
	}
	asn1Bytes, err := asn1.Marshal(pi)
	if err != nil {
		return pkix.Extension{}, err
	}
	// Hack: Change the string tag for unotice from IA5 to VisibleString. The
	// last part of asn1Bytes should be the IA5 tag, a length byte, and the
	// unotice string.
	i := len(asn1Bytes) - len(unotice)
	if i < 2 || (int)(asn1Bytes[i-1]) != len(unotice) || asn1Bytes[i-2] != asn1PrintableStringTag {
		return pkix.Extension{}, fmt.Errorf("Unexpected asn1 encoding: i=%d asn1=% x", i, asn1Bytes)
	}
	asn1Bytes[i-2] = asn1VisibleStringTag
	ext := pkix.Extension{
		Id:       idCertificatePolicies,
		Critical: false,
		Value:    asn1Bytes,
	}
	return ext, nil
}
