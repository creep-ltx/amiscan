package rardecode

import (
	"io"
)

const audioSize = 257

type decoder20 struct {
	br      *rarBitReader
	size    int64 // unpacked bytes left to be decompressed
	hdrRead bool  // block header has been read
	isAudio bool  // current block is Audio
	tail    bool  // this file's end has been checked for the next tables (BBX patch)

	codeLength [audioSize * 4]byte

	lz    *lz20Decoder
	audio *audio20Decoder
}

func (d *decoder20) version() int { return decode20Ver }

// init intializes the decoder for decoding a new file.
func (d *decoder20) init(r byteReader, reset bool, size int64, ver int) {
	if d.br == nil {
		d.br = newRarBitReader(r)
	} else {
		d.br.reset(r)
	}
	d.size = size
	d.tail = false
	if reset {
		d.hdrRead = false
		d.isAudio = false
		if d.audio != nil {
			d.audio.reset()
		}
		clear(d.codeLength[:])
	}
	if size == 0 {
		// unrar unpacks an empty file too: its data can hold the tables
		// the next file of a solid archive uses (BBX patch).
		d.finish()
	}
}

// finish does what unrar does when a file's bytes are all out: read the
// tables if this file never did, then the tables that RAR 2.x stores at a
// file's end for the next file of a solid archive (unrar's ReadLastTables).
// BBX patch.
func (d *decoder20) finish() {
	if d.tail {
		return
	}
	d.tail = true
	if !d.hdrRead {
		if err := d.readBlockHeader(); err != nil {
			d.hdrRead = false
			return
		}
	}
	var sym int
	var err error
	if d.isAudio {
		sym, err = d.audio.decoders[d.audio.curChan].readSym(d.br)
		if err != nil || sym != 256 {
			return
		}
	} else {
		sym, err = d.lz.mainDecoder.readSym(d.br)
		if err != nil || sym != 269 {
			return
		}
	}
	// Garbage at the very end can look like a table switch; keep the old
	// tables if the new ones cannot be read.
	saved := d.codeLength
	wasAudio := d.isAudio
	var chans, cur int
	if d.audio != nil {
		chans, cur = d.audio.chans, d.audio.curChan
	}
	if err := d.readBlockHeader(); err != nil {
		d.codeLength = saved
		d.isAudio = wasAudio
		if d.audio != nil {
			d.audio.chans, d.audio.curChan = chans, cur
		}
		d.hdrRead = true
	}
}

func readCodeLengthTable20(br *rarBitReader, table []byte) error {
	var bitlength [19]byte
	for i := 0; i < len(bitlength); i++ {
		n, err := br.readBits(4)
		if err != nil {
			return err
		}
		bitlength[i] = byte(n)
	}

	var bl huffmanDecoder
	bl.init(bitlength[:])

	for i := 0; i < len(table); {
		l, err := bl.readSym(br)
		if err != nil {
			return err
		}
		if l < 16 {
			table[i] = (table[i] + byte(l)) & 0xf
			i++
			continue
		}
		if l == 16 {
			if i == 0 {
				return ErrInvalidLengthTable
			}
			var n int
			n, err = br.readBits(2)
			if err != nil {
				return err
			}
			n += 3
			n = min(i+n, len(table))
			v := table[i-1]
			for i < n {
				table[i] = v
				i++
			}
			continue
		}
		var n int
		if l == 17 {
			n, err = br.readBits(3)
			if err != nil {
				return err
			}
			n += 3
		} else {
			n, err = br.readBits(7)
			if err != nil {
				return err
			}
			n += 11
		}
		n = min(i+n, len(table))
		clear(table[i:n])
		i = n
	}
	return nil
}

func (d *decoder20) readBlockHeader() error {
	n, err := d.br.readBits(1)
	if err != nil {
		return err
	}
	d.isAudio = n > 0
	n, err = d.br.readBits(1)
	if err != nil {
		return err
	}
	if n == 0 {
		clear(d.codeLength[:])
	}
	if d.isAudio {
		if d.audio == nil {
			d.audio = new(audio20Decoder)
		}
		err = d.audio.init(d.br, d.codeLength[:])
	} else {
		if d.lz == nil {
			d.lz = new(lz20Decoder)
		}
		err = d.lz.init(d.br, d.codeLength[:])
	}
	d.hdrRead = true
	return err
}

func (d *decoder20) fill(dr *decodeReader) error {
	for d.size > 0 && dr.notFull() {
		if !d.hdrRead {
			if err := d.readBlockHeader(); err != nil {
				return err
			}
		}
		var n int64
		var err error
		if d.isAudio {
			n, err = d.audio.fill(dr, d.size)
		} else {
			n, err = d.lz.fill(dr, d.size)
		}
		d.size -= n
		switch err {
		case nil:
			continue
		case errEndOfBlock:
			d.hdrRead = false
			continue
		case io.EOF:
			err = ErrDecoderOutOfData
		}
		return err
	}
	if d.size <= 0 {
		// A match can run past the end of corrupt data, leaving the size
		// negative; the original then returned nil for ever (BBX patch).
		d.finish()
		return io.EOF
	}
	return nil
}
