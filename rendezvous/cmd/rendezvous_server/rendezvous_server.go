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

// rendezvous acts as a nameserver to resolve service names into bindings that
// contain network addresss, ports, keys, and other information.
//
// For example, it might resolve "cloudproxy https ca" into
// {
//   Name: "cloudproxy https ca"
//   Host: "192.168.1.2",
//   Port: "8444",
//   Protocol: "tao+rpc",
//   Principal: key([...]).prog(...)
//   TTL: 300*time.Seconds
//   Age: 200*time.Seconds
// }
//
// * Manual (no policy)
//   In this mode, we rely on manual intervention to approve registration
//   requests, presumably after some out-of-band screening process has been
//   completed.
//
// * FCFS (first come first serve)
//   In this mode, registration requests are approved so long as they don't
//   conflict with an existing registration.
//
// * Automated (with policy)
//   In this mode, a policy dictates which registration requests should be
//   approved.
//
// Requests:
//   Register <binding>
//   Lookup <name regex>
//   Policy
// Responses:
//   OK [ <none> | <list of bindings> | <policy string> ]
//   ERROR <msg>

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/jlmucb/cloudproxy/go/util/verbose"
	"github.com/kevinawalsh/taoca/netlog"
	"github.com/kevinawalsh/taoca/rendezvous"
)

var opts = []options.Option{
	// Flags for all commands
	{"addr", "0.0.0.0:8111", "<ip:port>", "Address for listening", "all,persistent"},
	{"anon", false, "", "Allow anonymous requests", "all,persistent"},
	{"manual", false, "", "Require manual approval of requests", "all,persistent"},
	{"fcfs", false, "", "Approve non-conflicting requests", "all,persistent"},
	{"config", "/etc/tao/rendezvous/rendezvous.config", "<file>", "Location for storing configuration", "all"},
	{"init", false, "", "Initialize configuration file", "all"},
}

func init() {
	options.Add(opts...)
}

var allowAnon, manualMode, fcfsMode bool

func doError(ms util.MessageStream, err error, status rendezvous.ResponseStatus, detail string) {
	if err != nil {
		fmt.Printf("error handling request: %s\n", err)
	}
	verbose.Printf("sending error response: status=%s detail=%q\n", status, detail)
	resp := &rendezvous.Response{
		Status:      &status,
		ErrorDetail: proto.String(detail),
	}
	sendResponse(ms, resp)
}

func sendResponse(ms util.MessageStream, resp *rendezvous.Response) {
	_, err := ms.WriteMessage(resp)
	if err != nil {
		fmt.Printf("error writing response: %s\n", err)
	}
}

type Binding struct {
	rendezvous.Binding
	added      time.Time
	expiration time.Time
	conn       *tao.Conn
}

var lock = &sync.RWMutex{}
var bindings = make(map[string]*Binding)

func expire(now time.Time) {
	for k, v := range bindings {
		v.Age = proto.Uint64(uint64(now.Sub(v.added)))
		if !v.expiration.IsZero() {
			ttl := int64(v.expiration.Sub(now))
			if ttl <= 0 {
				delete(bindings, k)
				verbose.Printf("Expired binding: %s\n", k)
			} else {
				v.Ttl = proto.Uint64(uint64(ttl))
			}
		}
	}
}

func doResponses(conn *tao.Conn) {
	defer conn.Close()

	var peer *string
	if conn.Peer() != nil {
		peer = proto.String(conn.Peer().String())
		verbose.Printf("Processing connection requests for peer %s\n", *peer)
		netlog.Log("rendezvous: connection from peer %s", *peer)
	} else {
		verbose.Printf("Processing connection requests for anonymous peer\n")
		netlog.Log("rendezvous: connection from anonymous")
	}

	for {
		var req rendezvous.Request
		if err := conn.ReadMessage(&req); err != nil {
			if err != io.EOF {
				doError(conn, err, rendezvous.ResponseStatus_RENDEZVOUS_BAD_REQUEST, "failed to read request")
			}
			break
		}
		doResponse(&req, conn, peer)
	}
	lock.Lock()
	for k, v := range bindings {
		if v.expiration.IsZero() && v.conn == conn {
			delete(bindings, k)
			verbose.Printf("Expired binding upon close: %s\n", k)
		}
	}
	lock.Unlock()
	verbose.Println("Done processing connection requests")

	if peer == nil {
		netlog.Log("rendezvous: connection closed from anonymous")
	} else {
		netlog.Log("rendezvous: connection closed from peer %s", *peer)
	}
}

func register(conn *tao.Conn, b *rendezvous.Binding, peer *string) bool {
	lock.Lock()
	defer lock.Unlock()
	expire(time.Now())
	conflict := bindings[*b.Name]
	renewal := (conflict != nil && ((conflict.Principal == nil && peer == nil) || *conflict.Principal == *peer))
	if verbose.Enabled || manualMode {
		fmt.Printf("\nA new registration request has been received:\n")
		fmt.Printf("  Name: %q\n", *b.Name)
		if b.Host != nil {
			fmt.Printf("  Host: %q\n", *b.Host)
		}
		if b.Port != nil {
			fmt.Printf("  Port: %q\n", *b.Port)
		}
		if b.Protocol != nil {
			fmt.Printf("  Protocol: %q\n", *b.Protocol)
		}
		if b.Ttl != nil {
			fmt.Printf("  TTL: %q\n", time.Duration(*b.Ttl))
		}
		if peer == nil {
			fmt.Printf("  Anonymous\n")
		} else {
			fmt.Printf("  Principal: %q\n", *peer)
		}
		if renewal {
			fmt.Printf("This request is a renewal of an existing binding.\n")
		} else if conflict != nil {
			fmt.Printf("This request conflicts with an existing binding (which will be deleted).\n")
		}
		fmt.Printf("\n")
	}
	approved := false
	if manualMode {
		var ok string
		for {
			ok = prompt("Approve this request?", "no")
			if ok == "yes" || ok == "no" {
				break
			}
			fmt.Printf("I don't understand %q. Please type yes or no.\n", ok)
		}
		approved = (ok == "yes")
	} else if fcfsMode {
		approved = (conflict == nil)
	} else {
		// TODO(kwalsh) implement policy
	}
	if approved {
		b.Principal = peer
		b.Age = proto.Uint64(0)
		t := time.Now()
		var exp time.Time
		if b.Ttl != nil {
			exp = t.Add(time.Duration(*b.Ttl))
		}
		bindings[*b.Name] = &Binding{
			Binding:    *b,
			added:      t,
			expiration: exp,
			conn:       conn,
		}
	}
	return approved
}

func doResponse(req *rendezvous.Request, conn *tao.Conn, peer *string) {
	verbose.Println("Processing request")

	// Check whether the request is well-formed
	switch *req.Type {
	case rendezvous.RequestType_RENDEZVOUS_REGISTER:
		b := req.Binding
		if b == nil {
			doError(conn, nil, rendezvous.ResponseStatus_RENDEZVOUS_BAD_REQUEST, "missing binding")
			return
		}
		if !allowAnon && peer == nil {
			doError(conn, nil, rendezvous.ResponseStatus_RENDEZVOUS_REQUEST_DENIED, "anonymous registration forbidden")
			return
		}
		if b.Principal != nil && (peer == nil || *b.Principal != *peer) {
			doError(conn, nil, rendezvous.ResponseStatus_RENDEZVOUS_BAD_REQUEST, "third party registration forbidden")
			return
		}
		approved := register(conn, b, peer)
		if !approved {
			doError(conn, nil, rendezvous.ResponseStatus_RENDEZVOUS_REQUEST_DENIED, "request is denied")
			return
		}
		status := rendezvous.ResponseStatus_RENDEZVOUS_OK
		resp := &rendezvous.Response{Status: &status}
		sendResponse(conn, resp)

	case rendezvous.RequestType_RENDEZVOUS_LOOKUP:
		q := ".*"
		if req.Query != nil {
			q = *req.Query
		}
		r, err := regexp.Compile(q)
		if err != nil {
			doError(conn, err, rendezvous.ResponseStatus_RENDEZVOUS_BAD_REQUEST, "bad query")
			return
		}
		var matches []*rendezvous.Binding
		lock.Lock()
		expire(time.Now())
		for k, v := range bindings {
			if r.MatchString(k) {
				b := v.Binding
				matches = append(matches, &b)
			}
		}
		lock.Unlock()
		fmt.Printf("Query [%s] ==> %d matches\n", q, len(matches))
		status := rendezvous.ResponseStatus_RENDEZVOUS_OK
		resp := &rendezvous.Response{Status: &status, Bindings: matches}
		sendResponse(conn, resp)

	case rendezvous.RequestType_RENDEZVOUS_POLICY:
		var policy string
		if manualMode {
			policy = "manual"
		} else if fcfsMode {
			policy = "fcfs"
		} else {
			policy = "unspecified"
		}
		if allowAnon {
			policy = "anon," + policy
		}
		status := rendezvous.ResponseStatus_RENDEZVOUS_OK
		resp := &rendezvous.Response{Status: &status, Policy: &policy}
		sendResponse(conn, resp)
	default:
		doError(conn, nil, rendezvous.ResponseStatus_RENDEZVOUS_BAD_REQUEST, "unrecognized request type")
		return
	}
}

func main() {
	verbose.Set(true)
	options.Parse()

	if *options.String["config"] != "" && !*options.Bool["init"] {
		err := options.Load(*options.String["config"])
		options.FailIf(err, "Can't load configuration")
	}

	if *options.Bool["init"] {
		cpath := *options.String["config"]
		if cpath == "" {
			options.Fail(nil, "Option -init requires option -config")
		}
		fmt.Println("Initializing configuration file: " + cpath)
		err := options.Save(cpath, "Tao rendezvous configuration", "persistent")
		options.FailIf(err, "Can't save configuration")
	}

	fmt.Println("Cloudproxy Rendezvous Service")

	if tao.Parent() == nil {
		options.Fail(nil, "can't continue: no host Tao available")
	}

	allowAnon = *options.Bool["anon"]
	manualMode = *options.Bool["manual"]
	fcfsMode = *options.Bool["fcfs"]
	addr := *options.String["addr"]

	netlog.Log("rendezvous: init")
	netlog.Log("rendezvous: allow anon? %v", allowAnon)
	netlog.Log("rendezvous: manual? %v", manualMode)
	netlog.Log("rendezvous: fcfs? %v", fcfsMode)
	netlog.Log("rendezvous: addr = %v", addr)

	// TODO(kwalsh) extend tao name with operating mode and policy

	err := tao.NewOpenServer(tao.ConnHandlerFunc(doResponses)).ListenAndServe(addr)
	options.FailIf(err, "server died")

	netlog.Log("rendezvous: done")
}

func prompt(msg, def string) string {
	fmt.Printf("%s [%s]: ", msg, def)
	line, hasMoreInLine, err := bufio.NewReader(os.Stdin).ReadLine()
	options.FailIf(err, "Bad input")
	if hasMoreInLine {
		options.Fail(nil, "Buffer overflow: Bad input")
	}
	s := strings.TrimSpace(string(line))
	if s == "" {
		s = def
	}
	return s
}
