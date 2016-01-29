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

package indent

import (
	"fmt"
	"io"
	"strings"
)

// Writer produces structured (indented) output.
type Writer interface {
	Printf(format string, a ...interface{}) (n int, err error)
	Println(a ...interface{}) (n int, err error)
	Headerf(format string, a ...interface{}) (n int, err error)
	Headerln(a ...interface{}) (n int, err error)
	Bold(format string, a ...interface{}) string
	Link(url, text string) string
	PrintHex(data []byte)
	PrintHeaderHex(text string, data []byte)
	Indent()
	Dedent()
	io.Writer
}

type TextWriter struct {
	io.Writer
	Width  int
	Level  int
	Prefix string
}

func NewTextWriter(w io.Writer, width int) *TextWriter {
	return &TextWriter{Writer: w, Width: width, Level: 0}
}

func (w *TextWriter) Printf(format string, a ...interface{}) (n int, err error) {
	return fmt.Fprintf(w, w.Prefix+format, a...)
}

func (w *TextWriter) Println(a ...interface{}) (n int, err error) {
	return fmt.Fprintln(w, w.Prefix, fmt.Sprint(a...))
}

func (w *TextWriter) Headerf(format string, a ...interface{}) (n int, err error) {
	n, err = w.Printf(format, a...)
	w.Indent()
	return
}

func (w *TextWriter) Headerln(a ...interface{}) (n int, err error) {
	n, err = w.Println(a...)
	w.Indent()
	return
}

func (w *TextWriter) Bold(format string, a ...interface{}) string {
	return fmt.Sprintf(format, a...)
}

func (w *TextWriter) Link(url, text string) string {
	return url
}

func (w *TextWriter) PrintHex(data []byte) {
	n := 80 / 3
	i := 0
	for i < len(data) {
		if n > len(data)-i {
			n = len(data) - i
		}
		fmt.Fprintf(w, w.Prefix+"% 02x\n", data[i:i+n])
		i += n
	}
}

func (w *TextWriter) PrintHeaderHex(text string, data []byte) {
	n := 80 / 3
	i := 0
	fmt.Fprintf(w, w.Prefix+"%s (%d bytes)\n", text, len(data))
	for i < len(data) {
		if n > len(data)-i {
			n = len(data) - i
		}
		fmt.Fprintf(w, w.Prefix+"  % 02x\n", data[i:i+n])
		i += n
	}
}

func (w *TextWriter) Indent() {
	w.Level++
	w.Prefix = strings.Repeat(" ", w.Width*w.Level)
}

func (w *TextWriter) Dedent() {
	if w.Level > 0 {
		w.Level--
		w.Prefix = strings.Repeat(" ", w.Width*w.Level)
	}
}

type HtmlWriter struct {
	io.Writer
	Headers []string
	Level   int
}

func NewHtmlWriter(w io.Writer, headers ...string) *HtmlWriter {
	if len(headers) == 0 {
		headers = append(headers, "p")
	}
	return &HtmlWriter{Writer: w, Headers: headers, Level: 0}
}

func (w *HtmlWriter) Printf(format string, a ...interface{}) (n int, err error) {
	return fmt.Fprintf(w, "<"+w.Tag()+">"+format+"</"+w.Tag()+">", a...)
}

func (w *HtmlWriter) Println(a ...interface{}) (n int, err error) {
	return fmt.Fprintln(w, "<"+w.Tag()+">", fmt.Sprint(a...), "</"+w.Tag()+">")
}

func (w *HtmlWriter) Headerf(format string, a ...interface{}) (n int, err error) {
	n, err = w.Printf(format, a...)
	w.Indent()
	return
}

func (w *HtmlWriter) Headerln(a ...interface{}) (n int, err error) {
	n, err = w.Println(a...)
	w.Indent()
	return
}

func (w *HtmlWriter) Bold(format string, a ...interface{}) string {
	return "<b>" + fmt.Sprintf(format, a...) + "</b>"
}

func (w *HtmlWriter) Link(url, text string) string {
	return fmt.Sprintf(`<a href="%s">%s</a>`, url, text)
}

func (w *HtmlWriter) PrintHex(data []byte) {
	n := 96 / 3
	i := 0
	fmt.Fprintf(w, "<"+w.Tag()+">\n")
	for i < len(data) {
		if n > len(data)-i {
			n = len(data) - i
		}
		fmt.Fprintf(w, "% 02x<br>\n", data[i:i+n])
		i += n
	}
	fmt.Fprintf(w, "</"+w.Tag()+">")
}

func (w *HtmlWriter) PrintHeaderHex(text string, data []byte) {
	n := 96 / 3
	i := 0
	fmt.Fprintf(w, "<"+w.Tag()+"> %s (%d bytes)<br>\n", text, len(data))
	for i < len(data) {
		if n > len(data)-i {
			n = len(data) - i
		}
		fmt.Fprintf(w, "%s % 02x<br>\n", strings.Repeat("&nbsp;", 6), data[i:i+n])
		i += n
	}
	fmt.Fprintf(w, "</"+w.Tag()+">")
}

func (w *HtmlWriter) Indent() {
	w.Level++
	if w.Level >= len(w.Headers) {
		fmt.Fprintln(w, "<ul>")
	}
}

func (w *HtmlWriter) Tag() string {
	if w.Level >= len(w.Headers) {
		return "li"
	}
	return w.Headers[w.Level]
}

func (w *HtmlWriter) Dedent() {
	if w.Level >= len(w.Headers) {
		fmt.Fprintln(w, "</ul>")
	}
	if w.Level > 0 {
		w.Level--
	}
}
