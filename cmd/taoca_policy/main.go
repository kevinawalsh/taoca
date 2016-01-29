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
	"fmt"
	"os"
	"strings"

	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/kevinawalsh/taoca/policy"
)

func main() {

	if len(os.Args) != 2 {
		fmt.Printf("usage: %s policy_file\n", os.Args[0])
		return
	}
	g, err := policy.Load(os.Args[1])
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("=== policy rules ===\n%s\n=== end rules ===\n", g)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("$ ")
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "add ") {
			err = g.AddRule(line[4:])
		} else if strings.HasPrefix(line, "show") {
			fmt.Println(g)
		} else if strings.HasPrefix(line, "auth") {
			var prin auth.Prin
			if _, err := fmt.Sscanf(line[5:], "%v", &prin); err != nil {
				fmt.Printf("%s: %s\n", err, line[5:])
			} else {
				ok := g.IsAuthorized(prin, "ClaimCertificate", nil)
				fmt.Println(ok)
			}
		} else {
			var ok bool
			ok, err = g.Query(line)
			fmt.Println(ok)
		}
		if err != nil {
			fmt.Println(err)
		}
	}
}
