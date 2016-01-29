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
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"sort"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/kevinawalsh/taoca/util/indent"
)

type ManifestHandler struct {
	URL  string
	Prin string
}

func (mh ManifestHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	name, ok := q["p"]
	if !ok || len(name) != 1 {
		w.Header().Set("Content-Type", "text/html")
		t, err := template.New("show").Parse(ManifestIndexTemplate)
		options.FailIf(err, "can't parse template")
		err = t.Execute(w, mh)
		options.FailIf(err, "can't execute template")
		return
	}
	fmt.Printf("request for: %s\n", name[0])
	var p auth.Prin
	if _, err := fmt.Sscanf("("+name[0]+")", "%v", &p); err != nil {
		http.NotFound(w, req)
		return
	}

	m := tao.DeriveManifest(&p)
	var b bytes.Buffer
	Dump(indent.NewHtmlWriter(&b, "h2"), tao.Manifest{"Principal Manifest": m})
	s := b.String()

	w.Header().Set("Content-Type", "text/html")
	t, err := template.New("show").Parse(ManifestTemplate)
	options.FailIf(err, "can't parse template")
	err = t.Execute(w, template.HTML(s))
	options.FailIf(err, "can't execute template")
}

var knownKeys = map[string]int{
	"Subprincipal Extension": 19,
	"Status":                 18,
	"Type":                   17,
	"Key":                    16,
	"Size":                   15,
	"Exponent":               14,
	"Modulus":                13,

	"Container Type":    12,
	"Name":              11,
	"ID":                10,
	"Path":              9,
	"Program Hash":      8,
	"Docker Image Name": 7,
	"Linux Host Path":   6,
	"Linux Host Hash":   5,
	"User ID":           4,
	"Group ID":          3,
	"Initial Directory": 2,
	"Docker Rules Path": 1,

	"Parent": -1,
}

type knownKeysFirst []string

func (a knownKeysFirst) Len() int      { return len(a) }
func (a knownKeysFirst) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a knownKeysFirst) Less(i, j int) bool {
	oi := -knownKeys[a[i]]
	oj := -knownKeys[a[j]]
	if oi < oj {
		return true
	} else if oi > oj {
		return false
	} else {
		return a[i] < a[j]
	}
}

func Dump(w indent.Writer, m tao.Manifest) {
	keys := m.Keys()
	sort.Sort(knownKeysFirst(keys))
	for _, k := range keys {
		switch v := m[k].(type) {
		case tao.Manifest:
			w.Headerf("%s:\n", k)
			Dump(w, v)
			w.Dedent()
		case []byte:
			w.PrintHeaderHex(k, v)
		case auth.Bytes:
			w.PrintHeaderHex(k, []byte(v))
		default:
			w.Printf("%v: %v\n", k, w.Bold(fmt.Sprintf("%v", v)))
		}
	}
}

var ManifestIndexTemplate = `
<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>Cloudproxy X.509 Manifest Store</title>
</head>
<body>
<form action="{{.URL}}" method="get">
<p>Enter a principal name:</p>
<!-- <input type="text" name="p" size="100"> -->
<textarea name="p" rows="6" cols="100">{{.Prin}}</textarea>
<input type="submit" value="Submit">
</for>
</body></html>`

var ManifestTemplate = `
<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>Cloudproxy X.509 Certificate Store</title>
</head>
<body>
{{.}}
</body></html>`
