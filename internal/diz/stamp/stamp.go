// Package stamp reads the dates archives and disks store.
//
// MS-DOS and AmigaDOS dates are the wall clock of the machine that packed the
// file, with no zone: they come back with time.UTC as their location, so
// formatting them as they are shows what was stored. Unix seconds are a real
// instant and come back in the local zone. Either way, format without converting.
package stamp

import "time"

// DOS reads an MS-DOS date and time (two-second steps). Zero when the date
// is empty or impossible.
func DOS(date, tm uint16) time.Time {
	y, mo, d := 1980+int(date>>9), int(date>>5&15), int(date&31)
	h, mi, s := int(tm>>11), int(tm>>5&63), int(tm&31)*2
	if date == 0 || mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || s > 59 {
		return time.Time{}
	}
	return time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC)
}

// DOS32 reads the two as one little-endian word: time low, date high.
func DOS32(v uint32) time.Time { return DOS(uint16(v>>16), uint16(v)) }

// Amiga reads an AmigaDOS DateStamp: days since 1 January 1978, minutes
// since midnight, ticks (1/50 s) in the minute. Zero when empty or impossible.
func Amiga(days, mins, ticks uint32) time.Time {
	if days == 0 && mins == 0 && ticks == 0 || days > 60000 || mins >= 24*60 || ticks >= 60*50 {
		return time.Time{}
	}
	return time.Date(1978, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, int(days)).
		Add(time.Duration(mins)*time.Minute + time.Duration(ticks/50)*time.Second)
}

// Unix reads seconds since 1970, in the local zone. Zero for 0.
func Unix(s int64) time.Time {
	if s <= 0 {
		return time.Time{}
	}
	return time.Unix(s, 0)
}
