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
	"testing"
)

var _ = `
# This line should be ignored by the scanner.
# So should this line
This line should not be ignored.
This line should not be ignored, either \
and it should continue to this line \
and the\
se lines too.
`

func TestScanner(t *testing.T) {
	s, err := NewScanner("scanner_test.go")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for s.Scan() {
		n++
		line := s.Text()
		t.Logf("line %d %q", n, line)
	}
	if err = s.Err(); err != nil {
		t.Fatal(err)
	}
}
