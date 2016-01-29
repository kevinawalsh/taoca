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

package main

import (
	"fmt"

	"github.com/jlmucb/cloudproxy/go/tao"
)

func LoadPolicy(path string) (tao.Guard, error) {
	s, err := NewScanner(path)
	if err != nil {
		return nil, err
	}
	t := s.NextLine()
	var g tao.Guard
	switch t {
	case "acl":
		g = tao.NewACLGuard()
	case "datalog":
		g = tao.NewTemporaryDatalogGuard()
	case "":
		return nil, fmt.Errorf("%s: first line must specify 'datalog' or 'acl'\n", path)
	default:
		return nil, fmt.Errorf("%s: expected 'datalog' or 'acl', found %q\n", path, t)
	}
	for line := s.NextLine(); line != ""; line = s.NextLine() {
		err = g.AddRule(line)
		if err != nil {
			return nil, fmt.Errorf("%s: %s; processing this line:\n> %s\n", path, err, line)
		}
	}
	return g, nil
}

var defPolicy = `# This file defines the certificate-granting policy for some instance of a
# Cloudproxy HTTPS Certificate Authority. The format is as follows:
# 
# * Comment lines and blank lines are ignored. 
# * Most whitespace is ignored.
# * A '\' at the end of a non-comment line serves as a line continuation.
# * The first line specifies the type of policy, either "acl" or "datalog".
# * Remaining lines introduce rules, one per line.
#
# For an ACL-based guard, each rule is a triplet containing OU, CN, Prin.
# A wildcard '*' can be used for the OU and/or CN.
# For example:
#   ACL
#   Authorized("ClaimCertificate", key([...]).Program([...]), "Cloudproxy Password Checker" "192.168.1.3")
#   Authorized("ClaimCertificate", key([...]).Program([...]), "Cloudproxy Netlog Viewer", "192.168.1.4")
#   Authorized("ClaimCertificate", key([...]).Program([...]))
#
# For a Datalog-driven guard, each rule is a datalog formula.
#   Datalog
#   forall P: forall OU: forall CN: \
#              TrustedHttpsServerInstance(P, OU, CN) \
#              implies Authorized("ClaimCertificate", P, OU, CN)
#   forall P: forall OU: forall CN: forall Hash: \
#           TrustedHost(Host) and TrustedHttpsServer(Hash, OU, CN) \
#              and Subprin(P, Host, Hash) \
#              implies TrustedHttpsServerInstance(P, OU, CN) \
#   TrustedHttpsServer(ext.Program([....]))
#
acl
`
