package diz

import (
	"reflect"
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		max  int
		want []string
	}{
		{"plain", "Hello\r\nWorld\r\n", 10, []string{"Hello", "World"}},
		{"blank edges", "\n\n  \nText\n\nMore\n\n\n", 10, []string{"Text", "", "More"}},
		{"cut at 45", strings.Repeat("x", 50), 10, []string{strings.Repeat("x", 45)}},
		{"max lines", "1\n2\n3\n4\n5", 3, []string{"1", "2", "3"}},
		{"default 10", strings.Repeat("l\n", 15), 0, strings.Split(strings.Repeat("l\n", 10), "\n")[:10]},
		{"blank after cut", "1\n2\n\n4", 3, []string{"1", "2"}},
		{"tabs", "a\tb", 10, []string{"a    b"}},
		{"ansi", "\x1b[0;33mYellow\x1b[0m \x1b[2J\x1b7te\x1b(Bxt", 10, []string{"Yellow text"}},
		{"amiga csi", "\x9b0;32mGreen\x9b0m", 10, []string{"Green"}},
		{"amiga latin1", "Gr\xf6\xdfe f\xfcr \xc4rger \xa9 1994", 10, []string{"Größe für Ärger © 1994"}},
		{"pc blocks", "\xdb\xdb\xb2\xb1\xb0 \x84", 10, []string{"██▓▒░ ä"}},
		{"pc box", "\xc9\xcd\xcd\xcd\xbb\n\xc8\xcd\xcd\xcd\xbc", 10, []string{"╔═══╗", "╚═══╝"}},
		{"amiga art", "\xd8\xd8\xd8 Sk\xa1n \xb2", 10, []string{"ØØØ Sk¡n ²"}},
		{"sauce", "Desc\r\n\x1aSAUCE00 stuff", 10, []string{"Desc"}},
		{"controls", "a\x07b\x00c\x7fd", 10, []string{"abcd"}},
		{"utf8", "Smörgåsbord → 45", 10, []string{"Smörgåsbord → 45"}},
		{"empty", "\r\n \r\n", 10, nil},
		{"cr only", "one\rtwo", 10, []string{"one", "two"}},
	}
	for _, c := range cases {
		if got := Clean([]byte(c.raw), c.max); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestWrap(t *testing.T) {
	got := wrap("Contains: " + strings.Repeat("name.ext, ", 8))
	for _, l := range got {
		if len(l) > Width {
			t.Errorf("long line %q", l)
		}
	}
	if len(got) != 3 || got[0] != "Contains: name.ext, name.ext, name.ext," {
		t.Errorf("wrap: %q", got)
	}
	if got := wrap(strings.Repeat("y", 50)); len(got) != 2 || len(got[0]) != 45 {
		t.Errorf("long word: %q", got)
	}
}
