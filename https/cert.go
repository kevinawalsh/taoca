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

package https

import (
	"encoding/pem"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/kevinawalsh/taoca/util/indent"
	"github.com/kevinawalsh/taoca/util/x509txt"
)

type CertificateHandler struct {
	tao.CertificatePool
}

func (ch CertificateHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/cert/" || req.URL.Path == "/cert/index.html" {
		w.Header().Set("Content-Type", "text/html")
		var s []string
		for k, _ := range ch.Cert {
			s = append(s, k)
		}
		t, err := template.New("show").Parse(CertListTemplate)
		options.FailIf(err, "can't parse template")
		err = t.Execute(w, s)
		options.FailIf(err, "can't execute template")
		return
	}
	var name string
	_, err := fmt.Sscanf(req.URL.Path, "/cert/%s", &name)
	if err != nil {
		http.NotFound(w, req)
		return
	}
	fmt.Printf("request for: %s\n", name)
	form := ""
	for _, s := range []string{"der", "pem", "txt", "html"} {
		if strings.HasSuffix(name, "."+s) {
			name = name[0 : len(name)-len(s)-1]
			form = s
			break
		}
	}
	cert := ch.Cert[name]
	if cert == nil {
		http.NotFound(w, req)
		return
	}
	chain := ch.CertChain(name)
	switch form {
	case "der":
		if cert.IsCA {
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		} else {
			w.Header().Set("Content-Type", "application/x-x509-user-cert")
		}
		w.Write(cert.Raw)
	case "pem", "crt":
		w.Header().Set("Content-Type", "application/x-pem-file")
		for _, parent := range chain {
			s := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parent.Raw})
			w.Write(s)
		}
	case "txt":
		w.Header().Set("Content-Type", "text/plain")
		out := indent.NewTextWriter(w, 2)
		for _, cert := range chain {
			x509txt.Dump(out, cert)
		}
	case "html":
		w.Header().Set("Content-Type", "text/html")
		s := ""
		for _, cert := range chain {
			s += x509txt.Html(cert)
		}
		t, err := template.New("show").Parse(CertTemplate)
		options.FailIf(err, "can't parse template")
		err = t.Execute(w, template.HTML(s))
		options.FailIf(err, "can't execute template")
	default:
		http.NotFound(w, req)
	}
}

var CertListTemplate = `
<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>Cloudproxy X.509 Certificate Store</title>
</head>
<body>
<h2>Available Certificates</h2>
<ol>
	{{range . }}
	  <li><strong>{{ . }}</strong> [
	  <a href="{{.}}.der">DER</a> |
	  <a href="{{.}}.pem">PEM/CRT</a> |
	  <a href="{{.}}.txt">Plain Text</a> |
	  <a href="{{.}}.html">Pretty</a> ]
	  </li>
	{{else}}
	  <li><strong>None</strong></li>
	{{end}}
</ol>
</body></html>`

var CertTemplate = `
<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>Cloudproxy X.509 Certificate</title>
</head>
<body>
{{.}}
</body></html>`
