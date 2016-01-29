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

package netlog

import (
	"fmt"
	"strings"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// Server holds parameters for connecting to an HTTPS certificate authority
// server.
type Server struct {
	// Addr is the network address of the netlog server.
	Addr string
	// Conn is a Tao-authenticated connection to netlog server. It will be nil
	// until Connect() succeeds.
	Conn *tao.Conn

	// Guard, if not nil, authorizes the connection to the netlog server.
	Guard tao.Guard

	// DomainKey, if not nil, is used by Guard to authorize the connection.
	DomainKey *tao.Verifier
}

// DefaultServer is the default netlog server.
var DefaultServer = &Server{Addr: "0.0.0.0:8181", Guard: tao.LiberalGuard}

// Connect establishes a connection to a netlog server, if necessary. This will
// be called automatically by Log() and Entries().
func (srv *Server) Connect() error {
	if srv.Conn != nil {
		return nil
	}

	keys, err := tao.NewTemporaryTaoDelegatedKeys(tao.Signing, nil, tao.Parent())
	if err != nil {
		return err
	}

	conn, err := tao.Dial("tcp", srv.Addr, srv.Guard, srv.DomainKey, keys, nil)
	if err != nil {
		return err
	}

	srv.Conn = conn
	return nil
}

// Close the connection to a netlog server, if necessary.
func (srv *Server) Close() error {
	var err error
	if srv.Conn != nil {
		err = srv.Conn.Close()
		srv.Conn = nil
	}
	return err
}

// Log sends a formatted message to the default netlog server.
func Log(msg string, args ...interface{}) error {
	return DefaultServer.Log(msg, args...)
}

// Log sends a formatted message to a netlog server.
func (srv *Server) Log(msg string, args ...interface{}) error {
	if err := srv.Connect(); err != nil {
		return err
	}
	s := fmt.Sprintf(msg, args...)
	lines := strings.Split(s, "\n")
	for _, line := range lines {
		_, err := srv.Conn.WriteString("POST")
		if err != nil {
			return err
		}
		_, err = srv.Conn.WriteString(line)
		if err != nil {
			return err
		}
		resp, err := srv.Conn.ReadString()
		if err != nil {
			return err
		}
		if resp != "OK" {
			return fmt.Errorf("Unexpected response from netlog server %s: %s", srv.Addr, resp)
		}
	}
	return nil
}

type LogEntry struct {
	Prin auth.Prin
	Msg  string
}

// Entries gets messages from the default netlog server.
func Entries() ([]LogEntry, error) {
	return DefaultServer.Entries()
}

// Entries gets messages from a netlog server.
func (srv *Server) Entries() ([]LogEntry, error) {
	// TODO(kwalsh) use rpc to simplify this
	if err := srv.Connect(); err != nil {
		return nil, err
	}
	srv.Conn.WriteString("GET")
	resp, err := srv.Conn.ReadString()
	if err != nil {
		return nil, err
	}
	if resp != "OK" {
		return nil, fmt.Errorf("Unexpected response from netlog server %s: resp=%s", srv.Addr, resp)
	}
	n, err := srv.Conn.ReadInt()
	if err != nil {
		return nil, err
	}
	if n < 0 {
		return nil, fmt.Errorf("Malformed response from netlog server %s: n=%d", srv.Addr, n)
	}
	log := make([]LogEntry, 0, n)
	for i := 0; i < n; i++ {
		p, err := srv.Conn.ReadString()
		if err != nil {
			return nil, err
		}
		var prin auth.Prin
		if _, err := fmt.Sscan(p, &prin); err != nil {
			return nil, fmt.Errorf("Malformed response from netlog server %s: %s", srv.Addr, p)
		}
		msg, err := srv.Conn.ReadString()
		if err != nil {
			return nil, err
		}
		log = append(log, LogEntry{Prin: prin, Msg: msg})
	}
	return log, nil
}
