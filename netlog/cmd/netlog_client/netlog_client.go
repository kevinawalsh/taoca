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
	"strings"

	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/kevinawalsh/taoca/netlog"
)

func init() {
	options.AddOption("addr", "", "<ip:port>", "Address of netlog server", "all")
}

func main() {
	options.Help = "Usage: %s [options] (get|post ...)"
	options.Parse()

	srv := netlog.DefaultServer
	if *options.String["addr"] != "" {
		srv = &netlog.Server{Addr: *options.String["addr"]}
	}

	fmt.Printf("# connecting to netlog server %s using tao authentication.\n", srv.Addr)
	err := srv.Connect()
	options.FailIf(err, "couldn't connect to netlog server")

	args := options.Args()
	if len(args) == 1 && args[0] == "get" {
		log, err := srv.Entries()
		options.FailIf(err, "couldn't get netlog entries")
		fmt.Printf("# %d entries\n", len(log))
		for i, e := range log {
			fmt.Printf("%d %q %s\n", i, e.Prin, e.Msg)
		}
	} else if len(args) > 1 && args[0] == "post" {
		msg := strings.Join(args[1:], " ")
		err := srv.Log(msg)
		options.FailIf(err, "couldn't post netlog entry")
	} else {
		options.Usage("Unrecognized command: %s\n", args[0])
	}
}
