package cipher

import (
	"encoding/binary"
	"math/bits"
)

// -----------------------------------------------------------------
// 319FC5AB-EC0E-46B9-A252-2285F9DAE813 (Android Triple modified-TEA ECB)
// -----------------------------------------------------------------

type teaTripleECBAndroid struct {
	k [3][4]uint32
}

func NewTEATripleECBAndroid(key []byte) Cipher {
	c := &teaTripleECBAndroid{}
	for layer := 0; layer < 3; layer++ {
		for i := 0; i < 4; i++ {
			c.k[layer][i] = binary.BigEndian.Uint32(key[(layer*4+i)*4 : (layer*4+i+1)*4])
		}
	}
	return c
}

func teaModifiedEncLayer(v0, v1 *uint32, k [4]uint32) {
	a, b := *v0, *v1
	var sum uint32 = 0
	for {
		a += (b ^ sum) + k[sum&3] + ((b << 4) ^ (b >> 5))
		sum -= 0x61C88647
		b += k[(sum>>11)&3] + (a ^ sum) + ((a << 4) ^ (a >> 5))
		if sum == 0xC6EF3720 {
			break
		}
	}
	*v0, *v1 = a, b
}

func teaModifiedDecLayer(v0, v1 *uint32, k [4]uint32) {
	a, b := *v0, *v1
	var sum uint32 = 0xC6EF3720
	var kidx uint32 = 0x28B7BD67
	for {
		b -= (a ^ sum) + ((a << 4) ^ (a >> 5)) + k[(sum>>11)&3]
		sum += 0x61C88647
		a -= k[kidx&3] + (b ^ kidx) + ((b << 4) ^ (b >> 5))
		kidx += 0x61C88647
		if sum == 0 {
			break
		}
	}
	*v0, *v1 = a, b
}

func (c *teaTripleECBAndroid) Encrypt(text string) string {
	data := []byte(text)
	padded := padZero(data, 8)
	if len(padded) == 0 {
		padded = make([]byte, 8)
	}

	buf := make([]byte, len(padded))
	copy(buf, padded)

	for off := 0; off < len(buf); off += 8 {
		v0 := binary.BigEndian.Uint32(buf[off : off+4])
		v1 := binary.BigEndian.Uint32(buf[off+4 : off+8])
		teaModifiedEncLayer(&v0, &v1, c.k[0])
		teaModifiedEncLayer(&v0, &v1, c.k[1])
		teaModifiedEncLayer(&v0, &v1, c.k[2])
		binary.BigEndian.PutUint32(buf[off:off+4], v0)
		binary.BigEndian.PutUint32(buf[off+4:off+8], v1)
	}

	return hexEncode(buf)
}

func (c *teaTripleECBAndroid) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) < 8 || len(data)%8 != 0 {
		return ""
	}

	buf := make([]byte, len(data))
	copy(buf, data)

	for off := 0; off < len(buf); off += 8 {
		v0 := binary.BigEndian.Uint32(buf[off : off+4])
		v1 := binary.BigEndian.Uint32(buf[off+4 : off+8])
		teaModifiedDecLayer(&v0, &v1, c.k[2])
		teaModifiedDecLayer(&v0, &v1, c.k[1])
		teaModifiedDecLayer(&v0, &v1, c.k[0])
		binary.BigEndian.PutUint32(buf[off:off+4], v0)
		binary.BigEndian.PutUint32(buf[off+4:off+8], v1)
	}

	return string(stripTrailingZeros(buf))
}

// -----------------------------------------------------------------
// 35101415-A20F-4DFE-B00B-0B4F3B2F8C66 (Android Triple modified-TEA CBC)
// -----------------------------------------------------------------

type teaTripleCBCAndroid struct {
	k  [3][4]uint32
	iv [2]uint32
}

func NewTEATripleCBCAndroid(key, iv []byte) Cipher {
	c := &teaTripleCBCAndroid{}
	for layer := 0; layer < 3; layer++ {
		for i := 0; i < 4; i++ {
			c.k[layer][i] = binary.BigEndian.Uint32(key[(layer*4+i)*4 : (layer*4+i+1)*4])
		}
	}
	c.iv[0] = binary.BigEndian.Uint32(iv[0:4])
	c.iv[1] = binary.BigEndian.Uint32(iv[4:8])
	return c
}

func (c *teaTripleCBCAndroid) Encrypt(text string) string {
	data := []byte(text)
	padded := padZero(data, 8)
	if len(padded) == 0 {
		padded = make([]byte, 8)
	}

	buf := make([]byte, len(padded))
	copy(buf, padded)

	prev0 := c.iv[0]
	prev1 := c.iv[1]

	for off := 0; off < len(buf); off += 8 {
		v0 := binary.BigEndian.Uint32(buf[off:off+4]) ^ prev0
		v1 := binary.BigEndian.Uint32(buf[off+4:off+8]) ^ prev1
		// 加密顺序：k[2] -> k[1] -> k[0]
		teaModifiedEncLayer(&v0, &v1, c.k[2])
		teaModifiedEncLayer(&v0, &v1, c.k[1])
		teaModifiedEncLayer(&v0, &v1, c.k[0])
		binary.BigEndian.PutUint32(buf[off:off+4], v0)
		binary.BigEndian.PutUint32(buf[off+4:off+8], v1)
		prev0 = v0
		prev1 = v1
	}

	return hexEncode(buf)
}

func (c *teaTripleCBCAndroid) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) < 8 || len(data)%8 != 0 {
		return ""
	}

	buf := make([]byte, len(data))
	copy(buf, data)

	prev0 := c.iv[0]
	prev1 := c.iv[1]

	for off := 0; off < len(buf); off += 8 {
		c0 := binary.BigEndian.Uint32(buf[off : off+4])
		c1 := binary.BigEndian.Uint32(buf[off+4 : off+8])
		v0, v1 := c0, c1
		// 解密顺序：k[0] -> k[1] -> k[2]
		teaModifiedDecLayer(&v0, &v1, c.k[0])
		teaModifiedDecLayer(&v0, &v1, c.k[1])
		teaModifiedDecLayer(&v0, &v1, c.k[2])
		v0 ^= prev0
		v1 ^= prev1
		binary.BigEndian.PutUint32(buf[off:off+4], v0)
		binary.BigEndian.PutUint32(buf[off+4:off+8], v1)
		prev0 = c0
		prev1 = c1
	}

	return string(stripTrailingZeros(buf))
}

// -----------------------------------------------------------------
// 60639D8B-272E-4A4D-976E-AA270987A169 (Linux XTEA Triple-layer ECB)
// -----------------------------------------------------------------

type modXTEALinux struct {
	k1 [4]uint32
	k2 [4]uint32
	k3 [4]uint32
}

func NewModXTEALinux(k1, k2, k3 [4]uint32) Cipher {
	return &modXTEALinux{
		k1: k1,
		k2: k2,
		k3: k3,
	}
}

func xteaBlockEncrypt(v0, v1 *uint32, key [4]uint32) {
	ks := [4]uint32{
		bits.ReverseBytes32(key[0]),
		bits.ReverseBytes32(key[1]),
		bits.ReverseBytes32(key[2]),
		bits.ReverseBytes32(key[3]),
	}
	var sum uint32 = 0
	for i := 0; i < 32; i++ {
		kB := ks[sum&3]
		*v0 += ((*v1 << 4) ^ (*v1 >> 5)) + (sum ^ *v1) + kB
		sum += 0x9E3779B9
		kA := ks[(sum>>11)&3]
		*v1 += ((*v0 << 4) ^ (*v0 >> 5)) + (*v0 ^ sum) + kA
	}
}

func xteaBlockDecrypt(v0, v1 *uint32, key [4]uint32) {
	ks := [4]uint32{
		bits.ReverseBytes32(key[0]),
		bits.ReverseBytes32(key[1]),
		bits.ReverseBytes32(key[2]),
		bits.ReverseBytes32(key[3]),
	}
	var sum uint32 = 0xC6EF3720
	for i := 0; i < 32; i++ {
		kA := ks[(sum >> 11) & 3]
		*v1 -= ((*v0 << 4) ^ (*v0 >> 5)) + (*v0 ^ sum) + kA
		sum -= 0x9E3779B9
		kB := ks[sum&3]
		*v0 -= ((*v1 << 4) ^ (*v1 >> 5)) + (sum ^ *v1) + kB
	}
}

func (c *modXTEALinux) Encrypt(text string) string {
	data := []byte(text)
	padded := padZero(data, 8)
	if len(padded) == 0 {
		padded = make([]byte, 8)
	}

	buf := make([]byte, len(padded))
	copy(buf, padded)

	for off := 0; off < len(buf); off += 8 {
		v0 := binary.BigEndian.Uint32(buf[off : off+4])
		v1 := binary.BigEndian.Uint32(buf[off+4 : off+8])
		xteaBlockEncrypt(&v0, &v1, c.k1)
		xteaBlockEncrypt(&v0, &v1, c.k2)
		xteaBlockEncrypt(&v0, &v1, c.k3)
		binary.BigEndian.PutUint32(buf[off:off+4], v0)
		binary.BigEndian.PutUint32(buf[off+4:off+8], v1)
	}

	return hexEncode(buf)
}

func (c *modXTEALinux) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) < 8 || len(data)%8 != 0 {
		return ""
	}

	buf := make([]byte, len(data))
	copy(buf, data)

	for off := 0; off < len(buf); off += 8 {
		v0 := binary.BigEndian.Uint32(buf[off : off+4])
		v1 := binary.BigEndian.Uint32(buf[off+4 : off+8])
		xteaBlockDecrypt(&v0, &v1, c.k3)
		xteaBlockDecrypt(&v0, &v1, c.k2)
		xteaBlockDecrypt(&v0, &v1, c.k1)
		binary.BigEndian.PutUint32(buf[off:off+4], v0)
		binary.BigEndian.PutUint32(buf[off+4:off+8], v1)
	}

	return string(stripTrailingZeros(buf))
}

// -----------------------------------------------------------------
// AB6C8EBE-B8F8-4C08-8222-69A3B5E86A91 (Linux MOD_XTEA_CBC Triple)
// -----------------------------------------------------------------

type ab6c8Linux struct {
	k0 [4]uint32
	k1 [4]uint32
	k2 [4]uint32
	iv [2]uint32
}

func NewAB6C8Linux(k0, k1, k2 [4]uint32, iv [2]uint32) Cipher {
	return &ab6c8Linux{
		k0: k0,
		k1: k1,
		k2: k2,
		iv: iv,
	}
}

func ab6c8BlockEncrypt(v0, v1 *uint32, key [4]uint32) {
	ks := [4]uint32{
		bits.ReverseBytes32(key[0]),
		bits.ReverseBytes32(key[1]),
		bits.ReverseBytes32(key[2]),
		bits.ReverseBytes32(key[3]),
	}
	v9 := bits.ReverseBytes32(*v0)
	v10 := bits.ReverseBytes32(*v1)

	const delta uint32 = 1640531527 // 0x61C88647
	var j uint32 = 0

	for round := 0; round < 32; round++ {
		v6 := ks[j&3]
		v8 := ks[((j-delta)>>11)&3]
		v9 += ((16 * v10) ^ (v10 >> 5)) + (j ^ v10) + v6
		v10 += ((16 * v9) ^ (v9 >> 5)) + ((j - delta) ^ v9) + v8
		j -= delta
	}

	*v0 = bits.ReverseBytes32(v9)
	*v1 = bits.ReverseBytes32(v10)
}

func ab6c8BlockDecrypt(v0, v1 *uint32, key [4]uint32) {
	ks := [4]uint32{
		bits.ReverseBytes32(key[0]),
		bits.ReverseBytes32(key[1]),
		bits.ReverseBytes32(key[2]),
		bits.ReverseBytes32(key[3]),
	}
	v9 := bits.ReverseBytes32(*v0)
	v10 := bits.ReverseBytes32(*v1)

	var delta uint32 = 1640531527 // 0x61C88647
	j := uint32(0) - delta*32

	for round := 0; round < 32; round++ {
		v8 := ks[(j>>11)&3]
		v10 -= ((16 * v9) ^ (v9 >> 5)) + (j ^ v9) + v8
		j += delta
		v6 := ks[j&3]
		v9 -= ((16 * v10) ^ (v10 >> 5)) + (j ^ v10) + v6
	}

	*v0 = bits.ReverseBytes32(v9)
	*v1 = bits.ReverseBytes32(v10)
}

func (c *ab6c8Linux) Encrypt(text string) string {
	data := []byte(text)
	padded := padZero(data, 8)
	if len(padded) == 0 {
		padded = make([]byte, 8)
	}

	buf := make([]byte, len(padded))
	copy(buf, padded)

	chain0 := c.iv[0]
	chain1 := c.iv[1]

	for off := 0; off < len(buf); off += 8 {
		// 小端序读取
		v0 := binary.LittleEndian.Uint32(buf[off : off+4])
		v1 := binary.LittleEndian.Uint32(buf[off+4 : off+8])
		v0 ^= chain0
		v1 ^= chain1
		ab6c8BlockEncrypt(&v0, &v1, c.k2)
		ab6c8BlockEncrypt(&v0, &v1, c.k1)
		ab6c8BlockEncrypt(&v0, &v1, c.k0)
		binary.LittleEndian.PutUint32(buf[off:off+4], v0)
		binary.LittleEndian.PutUint32(buf[off+4:off+8], v1)
		chain0 = v0
		chain1 = v1
	}

	return hexEncode(buf)
}

func (c *ab6c8Linux) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) < 8 || len(data)%8 != 0 {
		return ""
	}

	buf := make([]byte, len(data))
	copy(buf, data)

	prev0 := c.iv[0]
	prev1 := c.iv[1]

	for off := 0; off < len(buf); off += 8 {
		// 小端序读取
		v0 := binary.LittleEndian.Uint32(buf[off : off+4])
		v1 := binary.LittleEndian.Uint32(buf[off+4 : off+8])
		c0, c1 := v0, v1
		ab6c8BlockDecrypt(&v0, &v1, c.k0)
		ab6c8BlockDecrypt(&v0, &v1, c.k1)
		ab6c8BlockDecrypt(&v0, &v1, c.k2)
		v0 ^= prev0
		v1 ^= prev1
		binary.LittleEndian.PutUint32(buf[off:off+4], v0)
		binary.LittleEndian.PutUint32(buf[off+4:off+8], v1)
		prev0 = c0
		prev1 = c1
	}

	return string(stripTrailingZeros(buf))
}
