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

package rendezvous

import (
	"fmt"
	"net"

	"github.com/jlmucb/cloudproxy/go/tao"
)

// Server holds parameters for connecting to a endezvous server.
type Server struct {
	Host, Port string
	conn       *tao.Conn
}

// DefaultServer is hosted on localhost at port 8111.
var DefaultServer = NewServer("0.0.0.0", "8111")

// Register a binding with the default server.
func Register(binding Binding) error {
	return DefaultServer.Register(binding)
}

// Lookup bindings from the default server.
func Lookup(query string) ([]*Binding, error) {
	return DefaultServer.Lookup(query)
}

// Policy gets a description of the policy of the default server.
func Policy() (string, error) {
	return DefaultServer.Policy()
}

// NewServer returns a new rendezvous Server for the given host and port.
func NewServer(host, port string) *Server {
	return &Server{
		Host: host,
		Port: port,
	}
}

// Register a binding with a rendezvous server.
func (s *Server) Register(binding Binding) error {
	if err := s.Connect(nil); err != nil {
		return err
	}
	t := RequestType_RENDEZVOUS_REGISTER
	req := &Request{Type: &t, Binding: &binding}
	_, err := s.conn.WriteMessage(req)
	if err != nil {
		return err
	}
	var resp Response
	if err := s.conn.ReadMessage(&resp); err != nil {
		return err
	}
	if *resp.Status != ResponseStatus_RENDEZVOUS_OK {
		detail := "unknown error"
		if resp.ErrorDetail != nil {
			detail = *resp.ErrorDetail
		}
		return fmt.Errorf("%s: %s", resp.Status, detail)
	}
	return nil
}

// Lookup bindings from a rendezvous server.
func (s *Server) Lookup(query string) ([]*Binding, error) {
	if err := s.Connect(nil); err != nil {
		return nil, err
	}
	t := RequestType_RENDEZVOUS_LOOKUP
	req := &Request{Type: &t, Query: &query}
	_, err := s.conn.WriteMessage(req)
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := s.conn.ReadMessage(&resp); err != nil {
		return nil, err
	}
	if *resp.Status != ResponseStatus_RENDEZVOUS_OK {
		detail := "unknown error"
		if resp.ErrorDetail != nil {
			detail = *resp.ErrorDetail
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, detail)
	}
	return resp.Bindings, nil
}

// Policy gets an description of the policy of a rendezvous server.
func (s *Server) Policy() (string, error) {
	if err := s.Connect(nil); err != nil {
		return "", err
	}
	t := RequestType_RENDEZVOUS_POLICY
	req := &Request{Type: &t}
	_, err := s.conn.WriteMessage(req)
	if err != nil {
		return "", err
	}
	var resp Response
	if err := s.conn.ReadMessage(&resp); err != nil {
		return "", err
	}
	if *resp.Status != ResponseStatus_RENDEZVOUS_OK {
		detail := "unknown error"
		if resp.ErrorDetail != nil {
			detail = *resp.ErrorDetail
		}
		return "", fmt.Errorf("%s: %s", resp.Status, detail)
	}
	if resp.Policy == nil {
		return "", nil
	}
	return *resp.Policy, nil
}

// Connect opens a connection to the server, if not already connected. If keys
// are provided, they will be used to connect. Otherwise, if running under a
// Tao, new Tao-delegated keys will be created to authenticate to the rendezvous
// server.
func (s *Server) Connect(keys *tao.Keys) error {
	if s.conn != nil {
		return nil
	}
	var err error
	if keys == nil && tao.Parent() != nil {
		keys, err = tao.NewTemporaryTaoDelegatedKeys(tao.Signing, nil, tao.Parent())
		if err != nil {
			return err
		}
	}
	addr := net.JoinHostPort(s.Host, s.Port)
	conn, err := tao.Dial("tcp", addr, nil /* guard */, nil /* verifier */, keys, nil)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

// Close closes the connection to the server, if already connected. All
// bindings registered using this connection that don't have an explicit TTL
// will be removed.
func (s *Server) Close() error {
	var err error
	conn := s.conn
	s.conn = nil
	if conn != nil {
		err = conn.Close()
	}
	return err
}
