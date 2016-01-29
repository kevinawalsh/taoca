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
	"bytes"
	"crypto/x509/pkix"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"path"
	"strings"
	"unicode"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/kevinawalsh/taoca"
	"github.com/kevinawalsh/taoca/https"
	"github.com/kevinawalsh/taoca/netlog"
)

var name = &pkix.Name{
	Country:            []string{"US"},
	Province:           []string{"MA"},
	Locality:           []string{"Oakham"},
	Organization:       []string{"Google"},
	OrganizationalUnit: []string{"CloudProxy HTTPS Netlog Viewer"},
	CommonName:         "",
}

var opts = []options.Option{
	// Flags for all commands
	{"host", "0.0.0.0", "<address>", "Address for listening", "all,persistent"},
	{"port", "8446", "<port>", "Port for listening", "all,persistent"},
	{"init", false, "", "Initialize fresh https keys and certificate", "all"},
	{"keys", "", "<dir>", "Directory for storing keys and associated certificates", "all,persistent"},
	{"config", "/etc/tao/netlog_https/netlog_https.config", "<file>", "Location for storing configuration", "all"},
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

	fmt.Println("Cloudproxy HTTPS Netlog Viewer")

	if tao.Parent() == nil {
		options.Fail(nil, "can't continue: no host Tao available")
	}

	// TODO(kwalsh) extend tao name with operating mode and policy

	addr := net.JoinHostPort(*options.String["host"], *options.String["port"])

	cpath := *options.String["config"]
	kdir := *options.String["keys"]
	if kdir == "" && cpath != "" {
		kdir = path.Dir(cpath)
	} else if kdir == "" {
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
		err := options.Save(cpath, "Cloudproxy HTTPS netlog viewer configuration", "persistent")
		options.FailIf(err, "Can't save configuration")
	}

	http.Handle("/cert/", https.CertificateHandler{keys.CertificatePool})
	http.Handle("/index.html", http.RedirectHandler("/", 301))
	http.HandleFunc("/", netlog_show)
	fmt.Printf("Listening at %s using HTTPS\n", addr)
	err := tao.ListenAndServeTLS(addr, keys)
	options.FailIf(err, "can't listen and serve")

	fmt.Println("Server Done")
}

type idMap struct {
	ids, parts map[string]string
	counts     map[string]int
}

func (m *idMap) pick(prefix, str string) string {
	if _, ok := m.parts[str]; !ok {
		m.counts[prefix]++
		m.parts[str] = fmt.Sprintf("%s%d", prefix, m.counts[prefix])
	}
	return m.parts[str]
}

func (m *idMap) add(prin auth.Prin) string {
	// Pick ids for the base principal name, i.e. the tao host
	//   key(...) --> keyi
	//   tpm(...) --> tpmi
	// Pick ids for all the subprincipal names
	//   Prog(...) --> Programi
	//   etc.
	p := prin.String()
	if s, ok := m.ids[p]; ok {
		return s
	}
	ext := prin.Ext
	prin.Ext = nil
	s := m.pick(template.HTMLEscapeString(prin.Type), prin.String())
	for _, e := range ext {
		s += "." + m.pick(e.Name, e.String())
	}
	tag := `<span class="id">[ %s ]<span class="pop"><span class="prin">%s</span></span></span>`
	m.ids[p] = fmt.Sprintf(tag, s, template.HTMLEscapeString(p))
	return m.ids[p]
}

// replace principals by a shorthand id and a popup
func compress(entries []netlog.LogEntry) []template.HTML {
	m := &idMap{
		ids:    make(map[string]string),
		parts:  make(map[string]string),
		counts: make(map[string]int),
	}
	var outs []template.HTML
	for _, entry := range entries {
		p := m.add(entry.Prin)
		// Scan for anything that looks like a principal name
		w := &bytes.Buffer{}
		w.WriteString(p)
		w.WriteString(" : ")
		r := strings.NewReader(entry.Msg)
		for {
			var prin auth.Prin
			var s string
			pos, _ := r.Seek(0, 1)
			if c, _, err := r.ReadRune(); err == nil && unicode.IsSpace(c) {
				w.WriteRune(c)
				continue
			}
			r.Seek(pos, 0)
			if _, err := fmt.Fscan(r, &prin); err == nil {
				w.WriteString(m.add(prin))
				continue
			}
			r.Seek(pos, 0)
			if _, err := fmt.Fscan(r, &s); err == nil {
				w.WriteString(template.HTMLEscapeString(s))
				continue
			}
			break
		}
		outs = append(outs, template.HTML(w.String()))
	}
	return outs
}

func netlog_show(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	e, err := netlog.Entries()
	if err != nil {
		t, _ := template.New("error").Parse(err_tpl)
		err = t.Execute(w, err)
		if err != nil {
			fmt.Printf("error showing netlog: %s\n", err)
		}
		return
	}
	s := compress(e)
	t, err := template.New("show").Parse(show_tpl)
	options.FailIf(err, "can't parse template")
	err = t.Execute(w, s)
	options.FailIf(err, "can't execute template")
}

var show_tpl = `
<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>Cloudproxy HTTPS Netlog Viewer</title>
<style>
li {
    padding: 3px;
    margin: 3px;
    border: 1px solid #fff;
}
li:hover {
    background: #eef;
    border: 1px solid #dde;
}
li * {
    margin: 0;
    padding: 0;
}
.id {
	position: relative;
	color: #33d;
}
.prin {
    border: 1px solid #bbb;
    background: #dcd;
    padding: 5px;
    display: block;
    word-wrap: break-word;
    overflow: auto;
}
.pop {
    position: absolute;
	float: right;
    padding: 25px 0 0 0;
    display: none;
    top: 0px;
    left: 0px;
    overflow: auto;
    width: 5in;
    z-index: 2;
}
.id:hover > .pop, .pop:hover {
    display: block;
}
</style></head>
<body>
<h2>Netlog entries:</h2>
<ol>
	{{range . }}
	  <li><span class="msg">{{ . }}</span></li>
	{{else}}
	  <li><strong>no log entries</strong></li>
	{{end}}
</ol>
</body></html>`

var err_tpl = `
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>Cloudproxy HTTPS Netlog Viewer</title>
	</head>
	<body>
		<h2>Error</h2>
		<p>{{ . }}</p>
	</body>
</html>`
