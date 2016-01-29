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

package policy

import (
	"bufio"
	"os"
	"regexp"
	"strings"
	"unicode"
)

// Note: Using protobuf text format might have been a better chioce here, but
// the format seems undocumented and I want to support comments and line
// continuations for human readability. Using json is another option.

type Scanner struct {
	*bufio.Scanner
}

func NewScanner(path string) (*Scanner, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	s := &Scanner{bufio.NewScanner(f)}
	s.Split(split)
	return s, nil
}

var continuations = regexp.MustCompile(`\\?\r?\n`)

func split(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	// Skip leading non-newline spaces.
	i := 0
	for i < len(data) && unicode.IsSpace(rune(data[i])) && data[i] != '\n' {
		i++
	}
	if i < len(data) && data[i] == '#' {
		// Comment lines end in newline.
		for ; i < len(data); i++ {
			if data[i] == '\n' {
				return i, []byte{}, nil
			}
		}
		// If we're at EOF, we have a final, non-terminated comment.
		if atEOF {
			return i, []byte{}, nil
		}
	} else {
		// Non-comment lines end in newline, but can have '\\' continuations.
		for ; i < len(data); i++ {
			if data[i] == '\n' && (i == 0 || data[i-1] != '\\') {
				out := continuations.ReplaceAll(data[0:i+1], nil)
				if out == nil {
					// Apparently bufio.Scanner() doesn't like nil tokens,
					// but regexp returns a nil token instead of blank.
					out = []byte{}
				}
				return i + 1, out, nil
			}
		}
		// If we're at EOF, we have a final, non-terminated line. Return it.
		if atEOF {
			return i, continuations.ReplaceAll(data[0:i], nil), nil
		}
	}
	// Need more data
	return 0, nil, nil
}

func (s *Scanner) NextLine() string {
	for ok := s.Scan(); ok; ok = s.Scan() {
		t := strings.TrimSpace(s.Text())
		if len(t) != 0 {
			return t
		}
	}
	return ""
}
