package lzx

import "errors"

var errCorrupt = errors.New("lzx: corrupt compressed data")

var tableOne = [32]uint32{
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14,
}

var tableTwo = [32]uint32{
	0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024,
	1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152,
}

var tableThree = [16]uint32{
	0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 4095, 8191, 16383, 32767,
}

var tableFour = [34]byte{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
}

const (
	bufTop = 258 + 65536 // end of the normal part of the output buffer
)

// decoder holds the state of unlzx's extract_normal for one merged group.
type decoder struct {
	src     []byte
	sp      int
	control uint32
	shift   int

	method     uint32
	length     int // decrunch_length: bytes left in this block
	lastOffset uint32

	offsetLen    [8]byte
	offsetTable  [256]uint16
	h20Len       [20]byte
	h20Table     [256]uint16
	literalLen   [768]byte
	literalTable [8192]uint16

	buf  []byte
	dest int
}

// refill is the C code's "if((shift -= n) < 0) { shift += 16; ... }" tail.
func (d *decoder) refill() {
	if d.shift < 0 {
		d.shift += 16
		d.control += uint32(d.src[d.sp]) << (8 + d.shift)
		d.control += uint32(d.src[d.sp+1]) << d.shift
		d.sp += 2
	}
}

// drop removes n bits.
func (d *decoder) drop(n uint32) {
	d.control >>= n
	d.shift -= int(n)
	d.refill()
}

// dropOne removes one bit, as the C code does inside the long-code loops.
func (d *decoder) dropOne() {
	if d.shift == 0 {
		d.shift = 15
		d.control += uint32(d.src[d.sp]) << 24
		d.control += uint32(d.src[d.sp+1]) << 16
		d.sp += 2
	} else {
		d.shift--
	}
	d.control >>= 1
}

func reverse(v uint32, bits uint32) uint32 {
	var leaf uint32
	for ; bits > 0; bits-- {
		leaf = leaf<<1 + v&1
		v >>= 1
	}
	return leaf
}

// makeDecodeTable builds a fast Huffman table from symbol bit lengths. It
// returns false when the lengths do not form a complete code.
func makeDecodeTable(numSymbols int, tableSize uint32, length []byte, table []uint16) bool {
	var pos uint32
	tableMask := uint32(1) << tableSize
	bitMask := tableMask >> 1
	bitNum := uint32(1)
	ok := true

	for ok && bitNum <= tableSize {
		for symbol := 0; symbol < numSymbols; symbol++ {
			if uint32(length[symbol]) == bitNum {
				leaf := reverse(pos, tableSize)
				pos += bitMask
				if pos > tableMask {
					ok = false
					break
				}
				next := uint32(1) << bitNum
				for fill := bitMask; fill > 0; fill-- {
					table[leaf] = uint16(symbol)
					leaf += next
				}
			}
		}
		bitMask >>= 1
		bitNum++
	}

	if ok && pos != tableMask {
		for symbol := pos; symbol < tableMask; symbol++ {
			table[reverse(symbol, tableSize)] = 0
		}
		nextSymbol := tableMask >> 1
		pos <<= 16
		tableMask <<= 16
		bitMask = 32768

		for ok && bitNum <= 16 {
			for symbol := 0; symbol < numSymbols; symbol++ {
				if uint32(length[symbol]) == bitNum {
					leaf := reverse(pos>>16, tableSize)
					for fill := uint32(0); fill < bitNum-tableSize; fill++ {
						if table[leaf] == 0 {
							table[nextSymbol<<1] = 0
							table[nextSymbol<<1+1] = 0
							table[leaf] = uint16(nextSymbol)
							nextSymbol++
						}
						leaf = uint32(table[leaf]) << 1
						leaf += (pos >> (15 - fill)) & 1
					}
					table[leaf] = uint16(symbol)
					pos += bitMask
					if pos > tableMask {
						ok = false
						break
					}
				}
			}
			bitMask >>= 1
			bitNum++
		}
	}
	if pos != tableMask {
		ok = false
	}
	return ok
}

// readH20 decodes one symbol of the 20-symbol code used for the lengths.
func (d *decoder) readH20() uint32 {
	symbol := uint32(d.h20Table[d.control&63])
	var n uint32
	if symbol >= 20 {
		for symbol >= 20 {
			symbol = uint32(d.h20Table[((d.control>>6)&1)+(symbol<<1)])
			d.dropOne()
		}
		n = 6
	} else {
		n = uint32(d.h20Len[symbol])
	}
	d.drop(n)
	return symbol
}

// readLiteralTable reads a block header: method, block length and tables.
func (d *decoder) readLiteralTable() bool {
	d.refill()
	d.method = d.control & 7
	d.drop(3)

	if d.method == 3 {
		for i := 0; i < 8; i++ {
			d.offsetLen[i] = byte(d.control & 7)
			d.drop(3)
		}
		if !makeDecodeTable(8, 7, d.offsetLen[:], d.offsetTable[:]) {
			return false
		}
	}

	length := int(d.control&255) << 16
	d.drop(8)
	length += int(d.control&255) << 8
	d.drop(8)
	length += int(d.control & 255)
	d.drop(8)
	d.length = length

	if d.method != 1 {
		pos, fix, maxSymbol := 0, uint32(1), 256
		for {
			for i := 0; i < 20; i++ {
				d.h20Len[i] = byte(d.control & 15)
				d.drop(4)
			}
			if !makeDecodeTable(20, 6, d.h20Len[:], d.h20Table[:]) {
				return false
			}
			for pos < maxSymbol {
				symbol := d.readH20()
				switch symbol {
				case 17, 18:
					var n, count uint32
					if symbol == 17 {
						n, count = 4, 3
					} else {
						n, count = 6-fix, 19
					}
					count += (d.control & tableThree[n]) + fix
					d.drop(n)
					for ; pos < maxSymbol && count > 0; count-- {
						d.literalLen[pos] = 0
						pos++
					}
				case 19:
					count := (d.control & 1) + 3 + fix
					d.dropOne()
					symbol = d.readH20()
					v := tableFour[uint32(d.literalLen[pos])+17-symbol]
					for ; pos < maxSymbol && count > 0; count-- {
						d.literalLen[pos] = v
						pos++
					}
				default:
					d.literalLen[pos] = tableFour[uint32(d.literalLen[pos])+17-symbol]
					pos++
				}
			}
			fix--
			maxSymbol += 512
			if maxSymbol != 768 {
				break
			}
		}
		if !makeDecodeTable(768, 12, d.literalLen[:], d.literalTable[:]) {
			return false
		}
	}
	return true
}

// decrunchBlock unpacks into buf from dest up to destEnd.
func (d *decoder) decrunchBlock(destEnd int) {
	for {
		symbol := uint32(d.literalTable[d.control&4095])
		if symbol >= 768 {
			d.drop(12)
			for symbol >= 768 {
				symbol = uint32(d.literalTable[(d.control&1)+(symbol<<1)])
				d.dropOne()
			}
		} else {
			d.drop(uint32(d.literalLen[symbol]))
		}
		if symbol < 256 {
			d.buf[d.dest] = byte(symbol)
			d.dest++
		} else {
			symbol -= 256
			t := symbol & 31
			count := tableTwo[t]
			n := tableOne[t]
			if n >= 3 && d.method == 3 {
				n -= 3
				count += (d.control & tableThree[n]) << 3
				d.drop(n)
				v := uint32(d.offsetTable[d.control&127])
				count += v
				n = uint32(d.offsetLen[v])
			} else {
				count += d.control & tableThree[n]
				if count == 0 {
					count = d.lastOffset
				}
			}
			d.drop(n)
			d.lastOffset = count

			t = (symbol >> 5) & 15
			count = tableTwo[t] + 3
			n = tableOne[t]
			count += d.control & tableThree[n]
			d.drop(n)

			from := d.dest - int(d.lastOffset)
			if int(d.lastOffset) >= d.dest {
				from += 65536
			}
			for ; count > 0; count-- {
				d.buf[d.dest] = d.buf[from]
				d.dest++
				from++
			}
		}
		if d.dest >= destEnd || d.sp >= len(d.src) {
			return
		}
	}
}

// decrunch unpacks a merged group's stream and returns its bytes from skip
// to skip+want; the bytes before skip are unpacked but not kept.
func decrunch(packed []byte, skip, want int64) ([]byte, error) {
	d := &decoder{
		src:        append(append(make([]byte, 0, len(packed)+1024), packed...), make([]byte, 1024)...),
		shift:      -16,
		lastOffset: 1,
		buf:        make([]byte, bufTop+1024),
	}
	out := make([]byte, 0, min(want, 16<<20))
	d.dest = bufTop
	pos := bufTop
	for int64(len(out)) < want {
		if pos == d.dest {
			if d.sp >= len(packed)+16 {
				return out, errCorrupt // ran out of data
			}
			if d.length <= 0 {
				if !d.readLiteralTable() {
					return out, errCorrupt
				}
			}
			if d.dest >= bufTop {
				n := d.dest - 65536
				copy(d.buf[0:n], d.buf[65536:d.dest])
				d.dest = n
				pos = n
			}
			destEnd := d.dest + d.length
			if destEnd > bufTop {
				destEnd = bufTop
			}
			start := d.dest
			d.decrunchBlock(destEnd)
			d.length -= d.dest - start
		}
		n := int64(d.dest - pos)
		if skip > 0 {
			k := min(n, skip)
			skip -= k
			pos += int(k)
			n -= k
		}
		if left := want - int64(len(out)); n > left {
			n = left
		}
		out = append(out, d.buf[pos:pos+int(n)]...)
		pos += int(n)
	}
	return out, nil
}
