// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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

// netlog_server provides an authenticated network log. Incoming log message are
// appended to the log, along with the verified tao principal name of the
// sender. Signed portions of the log can be requested.
//
// For now, the log is not written to disk and is not persistent.
//
// Requests:
//   "POST ..."
//   "GET"
// Responses:
//   "OK"
//   "BAD"
//   "DENIED"

package main

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/jlmucb/cloudproxy/go/util/verbose"
	"github.com/kevinawalsh/taoca/netlog"
)

func init() {
	options.AddOption("addr", "0.0.0.0:8181", "<ip:port>", "Address for listening", "all")
}

var log []*netlog.LogEntry

var lock = &sync.RWMutex{}

func doResponse(conn *tao.Conn) {
	defer conn.Close()

	if conn.Peer() == nil {
		verbose.Printf("netlog: connection from anonymous\n")
	} else {
		verbose.Printf("netlog: connection from peer %s\n", *conn.Peer())
	}

	for {
		req, err := conn.ReadString()
		if err == io.EOF {
			fmt.Fprintf(os.Stderr, "netlog: connection closed\n")
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "netlog: can't read: %s\n", err)
			break
		}

		verbose.Printf("netlog: got %s request\n", req)

		if req == "POST" {
			if conn.Peer() == nil {
				conn.WriteString("DENIED")
				break
			}
			verbose.Printf("netlog: peer is %s\n", *conn.Peer())
			msg, err := conn.ReadString()
			if err != nil {
				conn.WriteString("BAD")
				break
			}
			e := &netlog.LogEntry{Prin: *conn.Peer(), Msg: msg}
			lock.Lock()
			log = append(log, e)
			lock.Unlock()
			conn.WriteString("OK")
		} else if req == "GET" {
			lock.RLock()
			t := log
			lock.RUnlock()
			conn.WriteString("OK")
			conn.WriteInt(len(t))
			for _, e := range t {
				conn.WriteString(e.Prin.String())
				conn.WriteString(e.Msg)
			}
		} else {
			conn.WriteString("BAD")
			break
		}
	}

	if conn.Peer() == nil {
		verbose.Printf("netlog: connection closed from anonymous\n")
	} else {
		verbose.Printf("netlog: connection closed from peer %s\n", *conn.Peer())
	}
}

func main() {
	options.Parse()

	fmt.Println("Cloudproxy Networked Logging Service")

	if tao.Parent() == nil {
		options.Fail(nil, "can't continue: No host Tao available")
	}

	addr := *options.String["addr"]

	// TODO(kwalsh) perhaps extend our tao name with current config options

	err := tao.NewOpenServer(tao.ConnHandlerFunc(doResponse)).ListenAndServe(addr)
	options.FailIf(err, "netlog: server died")
}
