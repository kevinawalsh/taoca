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
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/http"
	"path"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/kevinawalsh/taoca"
	"github.com/kevinawalsh/taoca/https"
)

var name = &pkix.Name{
	Country:            []string{"US"},
	Province:           []string{"MA"},
	Locality:           []string{"Oakham"},
	Organization:       []string{"Google"},
	OrganizationalUnit: []string{"CloudProxy"},
	CommonName:         "",
}

var opts = []options.Option{
	// Flags for all commands
	{"host", "0.0.0.0", "<address>", "Address for listening", "all,persistent"},
	{"port", "8443", "<port>", "Port for listening", "all,persistent"},
	{"init", false, "", "Initialize fresh https keys and certificate", "all"},
	{"keys", "", "<dir>", "Directory for storing keys and associated certificates", "all,persistent"},
	{"docs", "", "<dir>", "Document root for serving files", "all,persistent"},
	{"config", "/etc/tao/https/https.config", "<file>", "Location for storing configuration", "all"},
}

func init() {
	options.Add(opts...)
}

func main() {
	options.Parse()
	if *options.String["config"] != "" && !*options.Bool["init"] {
		err := options.Load(*options.String["config"])
		options.FailIf(err, "Can't load configuration")
	}

	fmt.Println("Cloudproxy HTTPS Server")

	if tao.Parent() == nil {
		options.Fail(nil, "can't continue: no host Tao available")
	}
	self, err := tao.Parent().GetTaoName()
	options.FailIf(err, "Can't get Tao name")

	// TODO(kwalsh) extend tao name with operating mode and policy

	addr := net.JoinHostPort(*options.String["host"], *options.String["port"])

	cpath := *options.String["config"]
	kdir := *options.String["keys"]
	if kdir == "" && cpath != "" {
		kdir = path.Dir(cpath)
	} else if kdir == "" {
		options.Fail(nil, "Option -keys or -config is required")
	}

	docs := *options.String["docs"]
	if docs == "" && cpath != "" {
		docs = path.Join(path.Dir(cpath), "docs")
	} else if docs == "" {
		options.Fail(nil, "Option -keys or -config is required")
	}

	var keys *tao.Keys

	if *options.Bool["init"] {
		keys = taoca.GenerateKeys(name, addr, kdir)
	} else {
		keys = taoca.LoadKeys(kdir)
	}

	fmt.Printf("Configuration file: %s\n", cpath)
	if *options.Bool["init"] && cpath != "" {
		err := options.Save(cpath, "HTTPS server configuration", "persistent")
		options.FailIf(err, "Can't save configuration")
	}

	http.Handle("/cert/", https.CertificateHandler{keys.CertificatePool})
	http.Handle("/prin/", https.ManifestHandler{"/prin/", self.String()})
	http.Handle("/", http.FileServer(https.LoggingFilesystem{http.Dir(docs)}))
	fmt.Printf("Listening at %s using HTTPS\n", addr)
	err = tao.ListenAndServeTLS(addr, keys)
	options.FailIf(err, "can't listen and serve")

	fmt.Println("Server Done")
}
