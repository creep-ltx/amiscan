package amiga

import (
	"strconv"
	"strings"
)

// rawDoFmt formats like exec's RawDoFmt: arguments are 16-bit words unless
// the 'l' modifier is given; %s and %b take 32-bit pointers. It returns
// the text and the address just past the data used.
func (m *Machine) rawDoFmt(format, data uint32) (string, uint32) {
	fs := m.CString(format)
	var out strings.Builder
	for i := 0; i < len(fs); i++ {
		ch := fs[i]
		if ch != '%' {
			out.WriteByte(ch)
			continue
		}
		i++
		if i >= len(fs) {
			break
		}
		left, zero := false, false
		for ; i < len(fs) && (fs[i] == '-' || fs[i] == '0'); i++ {
			if fs[i] == '-' {
				left = true
			} else {
				zero = true
			}
		}
		width, limit := 0, -1
		for ; i < len(fs) && fs[i] >= '0' && fs[i] <= '9'; i++ {
			width = width*10 + int(fs[i]-'0')
		}
		if i < len(fs) && fs[i] == '.' {
			limit = 0
			for i++; i < len(fs) && fs[i] >= '0' && fs[i] <= '9'; i++ {
				limit = limit*10 + int(fs[i]-'0')
			}
		}
		long := false
		if i < len(fs) && fs[i] == 'l' {
			long = true
			i++
		}
		if i >= len(fs) {
			break
		}
		arg := func(signed bool) uint32 {
			if long {
				v := m.r32(data)
				data += 4
				return v
			}
			v := uint32(m.r16(data))
			data += 2
			if signed {
				v = uint32(int32(int16(v)))
			}
			return v
		}
		var s string
		switch fs[i] {
		case 'd':
			s = strconv.Itoa(int(int32(arg(true))))
		case 'u':
			s = strconv.FormatUint(uint64(arg(false)), 10)
		case 'x', 'X':
			s = strconv.FormatUint(uint64(arg(false)), 16)
			if fs[i] == 'X' {
				s = strings.ToUpper(s)
			}
		case 'c':
			s = string(rune(byte(arg(false))))
		case 's':
			p := m.r32(data)
			data += 4
			s = m.CString(p)
		case 'b':
			p := m.r32(data) << 2 // BSTR
			data += 4
			n := uint32(m.r8(p))
			s = string(m.Bytes(p+1, n))
		case '%':
			s = "%"
		default:
			s = string(fs[i])
		}
		if limit >= 0 && len(s) > limit {
			s = s[:limit]
		}
		for len(s) < width {
			switch {
			case left:
				s += " "
			case zero:
				s = "0" + s
			default:
				s = " " + s
			}
		}
		out.WriteString(s)
	}
	return out.String(), data
}
