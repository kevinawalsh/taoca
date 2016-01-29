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
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jlmucb/cloudproxy/go/util/options"
)

// LoggingFilesystem is an http.Filesystem that logs to fmt.Printf()
type LoggingFilesystem struct {
	Fs http.FileSystem
}

func (fs LoggingFilesystem) Open(name string) (http.File, error) {
	fmt.Printf("access: %s\n", name)
	return fs.Fs.Open(name)
}

func UrlBasename(loc string) string {
	u, err := url.ParseRequestURI(loc)
	options.FailIf(err, "can't parse url in certificate: %s", u)
	s := strings.Split(u.Path, "/")
	if len(s) < 2 {
		options.Fail(nil, "can't parse url in certificate: %s", u)
	}
	return s[len(s)-1]
}
