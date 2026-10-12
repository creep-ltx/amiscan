package update

import (
	"crypto"
	_ "crypto/md5" // PGP 2 signatures use MD5
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// Key is an RSA key from a PGP 2 (version 3) key block.
type Key struct {
	Owner string
	N, E  string // hex
	keyID uint64
	pub   *rsa.PublicKey
}

func (k *Key) init() {
	if k.pub != nil {
		return
	}
	n, _ := new(big.Int).SetString(k.N, 16)
	e, _ := new(big.Int).SetString(k.E, 16)
	k.pub = &rsa.PublicKey{N: n, E: int(e.Int64())}
	nb := n.Bytes()
	k.keyID = binary.BigEndian.Uint64(nb[len(nb)-8:]) // v3 key ID: low 64 bits of n
}

// Georg is Georg Wittmann's (formerly Hörmann) key, which signs
// xvs.library. Taken from https://www.vht-dk.dk/amiga/xvs/gh-pgp.txt; the
// same key is in the xvs archive as Georg.asc. Key ID 650EC4D80A831D77,
// fingerprint 2B53 8234 CBD3 4C5B 5F71 B8C3 6538 2290.
var Georg = &Key{
	Owner: "Georg Hoermann <ghoermann@gmx.de>",
	N: "a6efc0eb962523591c9c8da2699c8959158fdf07f8edf6a4fe3638cdb4587cb708cb861360f6b52430be4519" +
		"0810ccbdda984433fb2647f0fa11e96cd00596cdb1fee8cc274bbc14fee0da2bdf83df56e9c3293d7e8e5e0a" +
		"8899300c731a796b3ea66de999d0ae3e14131f0660d6b3edb6ebf20e5aeddf74650ec4d80a831d77",
	E: "11",
}

// VerifyPGP2 checks a detached PGP 2 signature (old packet format,
// version 3 signature, RSA) of data against key.
func VerifyPGP2(key *Key, data, sig []byte) error {
	key.init()
	if len(sig) < 3 || sig[0]&0x80 == 0 || sig[0]&0x40 != 0 || (sig[0]>>2)&15 != 2 {
		return errors.New("not a PGP 2 signature")
	}
	lenBytes := [4]int{1, 2, 4, 0}[sig[0]&3]
	if lenBytes == 0 || len(sig) < 1+lenBytes {
		return errors.New("bad signature packet")
	}
	n := 0
	for _, b := range sig[1 : 1+lenBytes] {
		n = n<<8 | int(b)
	}
	p := sig[1+lenBytes:]
	if len(p) < n || n < 19 {
		return errors.New("signature packet truncated")
	}
	p = p[:n]
	if (p[0] != 2 && p[0] != 3) || p[1] != 5 {
		return fmt.Errorf("unsupported signature version %d", p[0])
	}
	hashed := p[2:7] // signature type and creation time
	keyID := binary.BigEndian.Uint64(p[7:15])
	if p[15] != 1 {
		return errors.New("not an RSA signature")
	}
	var h crypto.Hash
	switch p[16] {
	case 1:
		h = crypto.MD5
	case 2:
		h = crypto.SHA1
	case 8:
		h = crypto.SHA256
	default:
		return fmt.Errorf("unsupported hash %d", p[16])
	}
	if keyID != key.keyID {
		return fmt.Errorf("signed by key %016X, not by %s", keyID, key.Owner)
	}
	mpi := p[19:]
	if len(mpi) < 2 {
		return errors.New("signature truncated")
	}
	bits := int(binary.BigEndian.Uint16(mpi))
	s := mpi[2:]
	if len(s) < (bits+7)/8 {
		return errors.New("signature truncated")
	}
	s = s[:(bits+7)/8]
	size := (key.pub.N.BitLen() + 7) / 8
	if len(s) > size {
		return errors.New("signature too long")
	}
	s = append(make([]byte, size-len(s)), s...)
	d := h.New()
	d.Write(data)
	d.Write(hashed)
	digest := d.Sum(nil)
	if digest[0] != p[17] || digest[1] != p[18] {
		return errors.New("signature does not match the file")
	}
	if err := rsa.VerifyPKCS1v15(key.pub, h, digest, s); err != nil {
		return errors.New("signature does not match the file")
	}
	return nil
}
