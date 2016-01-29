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
	"bufio"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"

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
	OrganizationalUnit: []string{"CloudProxy Password Checker"},
	CommonName:         "",
}

var opts = []options.Option{
	// Flags for all commands
	{"host", "0.0.0.0", "<address>", "Address for listening", "all,persistent"},
	{"port", "8445", "<port>", "Port for listening", "all,persistent"},
	{"init", false, "", "Initialize fresh https keys and certificate", "all"},
	{"keys", "", "<dir>", "Directory for storing keys and associated certificates", "all,persistent"},
	{"config", "/etc/tao/pwcheck/pwcheck.config", "<file>", "Location for storing configuration", "all"},
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

	fmt.Println("Cloudproxy HTTPS Password Checker")

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
	if cpath != "" {
		err := options.Save(cpath, "Cloudproxy HTTPS password checker configuration", "persistent")
		options.FailIf(err, "Can't save configuration")
	}

	http.Handle("/cert/", https.CertificateHandler{keys.CertificatePool})
	http.Handle("/index.html", http.RedirectHandler("/", 301))
	http.HandleFunc("/", pwcheck)
	fmt.Printf("Listening at %s using HTTPS\n", addr)
	err := tao.ListenAndServeTLS(addr, keys)
	options.FailIf(err, "can't listen and serve")

	fmt.Println("Server Done")
}

func pwcheck(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ps, ok := q["p"]
	if !ok || len(ps) == 0 {
		w.Header().Set("Content-Type", "text/html")
		body := fmt.Sprintf(html, "", "", "")
		w.Write([]byte(body))
		return
	}
	p := ps[0]
	_, desc, comments := PasswordStrength(p)
	li := ""
	for _, c := range comments {
		li += "<li>" + c + "</li>\n"
	}
	w.Header().Set("Content-Type", "text/html")
	desc = fmt.Sprintf("This password was found to be <b>%s</b>.", desc)
	body := fmt.Sprintf(html, p, desc, li)
	w.Write([]byte(body))
}

var html = `<html><head><title>Cloudproxy Password Checker</title></head>
<style>
b { color: #aa0000; font-weight: bold; font-style: normal; }
i { color: #00aa00; font-weight: bold; font-style: normal; }
span { color: #880088; font-weight: bold; font-style: normal; font-size: large; }
div { border: 1px solid black; width: 600px; margin: 0 50px; padding: 30px; }
</style>
<body>
<p>Enter a password below. This will be sent to a cloudproxy server, which will check the password's strength.</p>
<div>
<form action="/" method="get">
<p>Password: <input type="text" name="p" size="70" value="%s" /></p>
<p>If you trust this server, then <input type="submit" value="submit!"/></p>
</form>

<p>%s</p>
<ul>
%s
<ul>

</div>

<p>Note: This password checker is a proof of concept, and it does not perform
any sophisticated analysis. In principle, it could store and report on
frequently submitted passwords, check passwords against a proprietary database
of known passwords, etc.</p>

<p>All computations are done on a Cloudproxy HTTPs server, but the server does
not record or leak this password. Promise! In order to gain some assurance that
we aren't lying to you, you can do the following:
<ol>
  <li>Make sure you are accessing this site over a private <b>HTTPS
      connection</b>. This ensures you are really connecting with the
	  server holding some private key.</li>
  <li>Examine the HTTPS <b>x509 certificate</b> (e.g. click the lock, go to
	  <i>Connection</i>, then <i>Certificate Details</i>). Make sure it was
	  issued by a CloudProxy Certificate Authority (CA) that you trust. In
	  particular, you need to trust the CA to maintain the secrecy of its
	  private key and to only issue certificates that link to an accurate
	  representation of the practices and policies under which it approves
	  certificate signing requests.</li>
  <li>Next find the <b>Certificate Policies</b> within the x509 certificate
      (e.g. click <i>Details</i>). There you should find two URLs, the first linking
      to a <i>certification Practices Statement</i>, the second to a <i>User
      Notice</i>. Download these files (the links will point <a href="/security/">here</a>).</li>
  <li><b>Compute the sha256 hash of each file</b> and check that it matches the
	  hash in the corresponding URL. This step ensures the files haven't been
	  tampered with after they were generated by the certificate authority.
	  Since you trusted the CA in the previous step, you can now have some
	  assurance that you are looking at the actual policies under which your
	  trusted CA is running.</li>
  <li>Next, <b>examine the policy file contents</b>. Together, they give
	  details about this server's software and hardware. Mostly it is just a few
	  hashes and public keys, so you will need to check that the hash matches
	  the hash of software you trust and/or check to make sure the public key
	  corresponds to some entity you trust.</li>
  <li>You can now <b>decide if you trust that software and hardware</b> to properly
      implement https, protect the secrecy of the private https key, properly
      generate a random password, not record or leak the password, etc.</li>
</ol>

</body></html>`

// Code below was adapted from https://github.com/briandowns/GoPasswordUtilities
// which carries the following copyright notice and license.
//
// Copyright 2014 Brian J. Downs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var lower = regexp.MustCompile(`[a-z]`)
var upper = regexp.MustCompile(`[A-Z]`)
var digit = regexp.MustCompile(`[0-9]`)
var special = regexp.MustCompile(`[\!\@\#\$\%\^\&\*\(\\\)\-_\=\+\,\.\?\/\:\;\{\}\[\]~]`)

var descriptions = map[int]string{
	0: "extremely weak",
	1: "very weak",
	2: "weak",
	3: "not great",
	4: "okay",
	5: "good",
	6: "very good",
	7: "great",
}

// PasswordStrength returns a score from 0 to 4 along with a description and comments about
// the password strength of p.
func PasswordStrength(p string) (score int, desc string, comments []string) {
	if len(p) < 10 {
		comments = append(comments, "- too short to bother analyzing")
		desc = "extremely weak"
		return
	}
	score = 1
	if len(p) > 20 {
		comments = append(comments, "+ contains 20 or more characters")
		score++
	}
	if len(p) > 30 {
		comments = append(comments, "+ contains 30 or more characters")
		score++
	}
	if lower.MatchString(p) {
		comments = append(comments, "+ contains lowercase letters")
		score++
	}
	if upper.MatchString(p) {
		comments = append(comments, "+ contains uppercase letters")
		score++
	}
	if digit.MatchString(p) {
		comments = append(comments, "+ contains digits")
		score++
	}
	if special.MatchString(p) {
		comments = append(comments, "+ contains symbols")
		score++
	}
	if searchDict(p) {
		comments = append(comments, "- contains common dictionary words")
		score--
	}
	desc = descriptions[score]
	return
}

// Location of dict. We could use /usr/share/dict/words instead.
var wordsLocation = "/usr/share/dict/cracklib-small"

func searchDict(p string) bool {
	file, err := os.Open(wordsLocation)
	if err != nil {
		return true
	}
	defer file.Close()

	p = strings.ToLower(p)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		w := strings.ToLower(scanner.Text())
		if len(w) > 3 && (strings.Contains(w, p) || strings.Contains(p, w)) {
			return true
		}
	}
	return false
}
