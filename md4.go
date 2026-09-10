// SPDX-License-Identifier: BSD-3-Clause

package directory

import "encoding/binary"

// MD4, from RFC 1320, in ninety lines.
//
// It is here rather than as a dependency because this package has none, and
// because there is nowhere to take it from: the standard library does not have
// MD4 and golang.org/x/crypto's is deprecated, which is correct advice for
// anybody choosing a hash and irrelevant here.
//
// MD4 IS BROKEN as a hash function -- collisions are trivial and preimages are
// within reach -- and it is used anyway, because NTLMv2 is DEFINED over it.
// This is not a choice about security: it is the arithmetic Windows file
// sharing specifies, and a server computing anything else would refuse every
// correct password. Nothing here should be used for anything but that.
func md4sum(data []byte) []byte {
	// The state, from the specification.
	a, b, c, d := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476)

	// Padding: a 1 bit, then zeros to 56 mod 64, then the length in bits.
	n := len(data)
	padded := make([]byte, 0, n+72)
	padded = append(padded, data...)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	padded = binary.LittleEndian.AppendUint64(padded, uint64(n)*8)

	var x [16]uint32
	for off := 0; off < len(padded); off += 64 {
		for i := range x {
			x[i] = binary.LittleEndian.Uint32(padded[off+i*4:])
		}
		aa, bb, cc, dd := a, b, c, d

		round1 := func(a, b, c, d uint32, k int, s uint) uint32 {
			return rotl(a+((b&c)|(^b&d))+x[k], s)
		}
		round2 := func(a, b, c, d uint32, k int, s uint) uint32 {
			return rotl(a+((b&c)|(b&d)|(c&d))+x[k]+0x5a827999, s)
		}
		round3 := func(a, b, c, d uint32, k int, s uint) uint32 {
			return rotl(a+(b^c^d)+x[k]+0x6ed9eba1, s)
		}
		for i := 0; i < 4; i++ {
			k := i * 4
			a = round1(a, b, c, d, k+0, 3)
			d = round1(d, a, b, c, k+1, 7)
			c = round1(c, d, a, b, k+2, 11)
			b = round1(b, c, d, a, k+3, 19)
		}
		for i := 0; i < 4; i++ {
			a = round2(a, b, c, d, i+0, 3)
			d = round2(d, a, b, c, i+4, 5)
			c = round2(c, d, a, b, i+8, 9)
			b = round2(b, c, d, a, i+12, 13)
		}
		for _, i := range []int{0, 2, 1, 3} {
			a = round3(a, b, c, d, i+0, 3)
			d = round3(d, a, b, c, i+8, 9)
			c = round3(c, d, a, b, i+4, 11)
			b = round3(b, c, d, a, i+12, 15)
		}
		a, b, c, d = a+aa, b+bb, c+cc, d+dd
	}

	out := make([]byte, 0, 16)
	for _, v := range []uint32{a, b, c, d} {
		out = binary.LittleEndian.AppendUint32(out, v)
	}
	return out
}

func rotl(x uint32, n uint) uint32 { return x<<n | x>>(32-n) }
