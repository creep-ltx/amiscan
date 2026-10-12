package diz

import (
	"bytes"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
)

// Width is the FILE_ID.DIZ line width (spec v1.9: 45 columns).
const Width = 45

// DefaultLines is the FILE_ID.DIZ line count (spec v1.9: 10 lines).
const DefaultLines = 10

// Clean applies the DIZ rules to raw bytes of a description text: decode
// (CP437 if it has PC block or box drawing characters, else ISO-8859-1),
// strip ANSI escape sequences and other control characters, expand tabs, cut
// lines at 45 runes, drop blank lines at start and end, keep at most maxLines
// lines (maxLines <= 0 means 10).
func Clean(raw []byte, maxLines int) []string {
	return cleanText(decode(raw), maxLines)
}

// decode turns description bytes into text. Everything after a Ctrl-Z is
// dropped (the end of a DOS text file; SAUCE records follow it).
func decode(raw []byte) string {
	if i := bytes.IndexByte(raw, 0x1a); i >= 0 {
		raw = raw[:i]
	}
	utf := utf8.Valid(raw) && hasMultiByteUTF8(raw) // a modern DIZ written in UTF-8
	pc := !utf && isCP437(raw)
	raw = stripANSI(raw, !pc && !utf)
	if utf {
		return string(raw)
	}
	var b strings.Builder
	b.Grow(len(raw))
	for _, c := range raw {
		switch {
		case c < 0x80:
			b.WriteByte(c)
		case pc:
			b.WriteRune(charmap.CodePage437.DecodeByte(c))
		default:
			b.WriteRune(rune(c)) // ISO-8859-1 is the first 256 code points
		}
	}
	return b.String()
}

func hasMultiByteUTF8(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return true
		}
	}
	return false
}

// isCP437 decides whether the text is PC (CP437) rather than Amiga
// (ISO-8859-1). The PC blocks 0xB0 (░) and 0xDB (█) are taken as proof, as in
// dizlist, which was checked by eye on 3,871 archives. So is a run of three
// PC box lines, 0xC4 (───) or 0xCD (═══). Other bytes in 0xB1-0xDF are not:
// Amiga art uses ± ² · and letters like ØØØ, and Ä Ö Ü ß are in that range.
func isCP437(raw []byte) bool {
	if bytes.IndexByte(raw, 0xb0) >= 0 || bytes.IndexByte(raw, 0xdb) >= 0 {
		return true
	}
	return bytes.Contains(raw, []byte{0xc4, 0xc4, 0xc4}) || bytes.Contains(raw, []byte{0xcd, 0xcd, 0xcd})
}

// stripANSI removes ANSI escape sequences. Amiga text may also use the
// one-byte CSI 0x9B, which in CP437 is a printable character.
func stripANSI(raw []byte, amigaCSI bool) []byte {
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		csi := false
		switch {
		case c == 0x1b && i+1 < len(raw) && raw[i+1] == '[':
			csi = true
			i++
		case c == 0x9b && amigaCSI:
			csi = true
		case c == 0x1b:
			// Other escapes: intermediates, then one final byte (ESC 7, ESC ( B).
			for i+1 < len(raw) && raw[i+1] >= 0x20 && raw[i+1] <= 0x2f {
				i++
			}
			if i+1 < len(raw) && raw[i+1] >= 0x30 && raw[i+1] <= 0x7e {
				i++
			}
			continue
		}
		if !csi {
			out = append(out, c)
			continue
		}
		// Parameters and intermediates, then one final byte.
		for i+1 < len(raw) && raw[i+1] >= 0x20 && raw[i+1] <= 0x3f {
			i++
		}
		if i+1 < len(raw) && raw[i+1] >= 0x40 && raw[i+1] <= 0x7e {
			i++
		}
	}
	return out
}

// cleanText applies the line rules to decoded text.
func cleanText(t string, maxLines int) []string {
	if maxLines <= 0 {
		maxLines = DefaultLines
	}
	t = strings.ReplaceAll(t, "\r\n", "\n")
	t = strings.ReplaceAll(t, "\r", "\n")
	var out []string
	for _, line := range strings.Split(t, "\n") {
		out = append(out, cleanLine(line))
	}
	out = trimBlank(out)
	if len(out) > maxLines {
		out = trimBlank(out[:maxLines])
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// cleanLine expands tabs, drops control characters and cuts at Width.
func cleanLine(line string) string {
	var r []rune
	for _, c := range line {
		switch {
		case c == '\t':
			// Four spaces, as dizlist: scene DIZes drawn with tabs line up
			// that way (checked on real ones), not with 8-column stops.
			r = append(r, ' ', ' ', ' ', ' ')
		case c == 0xa0:
			r = append(r, ' ')
		case c < 0x20, c == 0x7f, c >= 0x80 && c < 0xa0, c == utf8.RuneError:
			// control character: drop
		default:
			r = append(r, c)
		}
	}
	if len(r) > Width {
		r = r[:Width]
	}
	return strings.TrimRightFunc(string(r), unicode.IsSpace)
}

func trimBlank(lines []string) []string {
	for len(lines) > 0 && lines[0] == "" {
		lines = lines[1:]
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// wrap breaks a long line at spaces into lines of at most Width runes, as
// dizlist does for readme text (a word longer than the line is cut).
func wrap(line string) []string {
	var out []string
	r := []rune(line)
	for len(r) > Width {
		cut := -1
		for i := Width; i >= 0; i-- {
			if r[i] == ' ' {
				cut = i
				break
			}
		}
		if cut <= 10 {
			cut = Width
		}
		out = append(out, strings.TrimRight(string(r[:cut]), " "))
		r = []rune(strings.TrimLeft(string(r[cut:]), " "))
	}
	return append(out, string(r))
}
