package amiga

import (
	"fmt"
	"strings"
)

// Amiga file names may hold characters Windows forbids (xfd's decruncher
// "Ace?"). On disk such characters are written %XX; the emulated Amiga
// sees the real name. Names without them are the same on both sides.

const hostForbidden = `<>:"\|?*%`

// HostName is the name to store an Amiga file under on any host.
func HostName(amiga string) string {
	if !strings.ContainsAny(amiga, hostForbidden) {
		return amiga
	}
	var b strings.Builder
	for i := 0; i < len(amiga); i++ {
		if c := amiga[i]; strings.IndexByte(hostForbidden, c) >= 0 || c < 32 {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// AmigaName is the name the emulated Amiga sees for a host file.
func AmigaName(host string) string {
	if !strings.Contains(host, "%") {
		return host
	}
	var b strings.Builder
	for i := 0; i < len(host); i++ {
		if host[i] == '%' && i+2 < len(host) {
			var v byte
			if _, err := fmt.Sscanf(host[i+1:i+3], "%02X", &v); err == nil {
				b.WriteByte(v)
				i += 2
				continue
			}
		}
		b.WriteByte(host[i])
	}
	return b.String()
}
