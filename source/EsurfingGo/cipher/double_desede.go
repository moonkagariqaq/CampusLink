package cipher

import (
	"crypto/cipher"
	"crypto/des"
)

// -----------------------------------------------------------------
// 9ABF4D29-34DB-4CE9-BB8C-7E371D637758 (Android double 3DES-CBC)
// -----------------------------------------------------------------

type desedeDoubleCBCAndroid struct {
	key []byte
	iv  []byte
}

func NewDESedeDoubleCBCAndroid(key, iv []byte) Cipher {
	return &desedeDoubleCBCAndroid{
		key: key,
		iv:  iv[:8],
	}
}

func des3CBCEncrypt(key24 []byte, iv8 []byte, data []byte) []byte {
	block, err := des.NewTripleDESCipher(key24)
	if err != nil {
		return nil
	}
	out := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv8)
	mode.CryptBlocks(out, data)
	return out
}

func des3CBCDecrypt(key24 []byte, iv8 []byte, data []byte) []byte {
	block, err := des.NewTripleDESCipher(key24)
	if err != nil {
		return nil
	}
	out := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, iv8)
	mode.CryptBlocks(out, data)
	return out
}

func (c *desedeDoubleCBCAndroid) Encrypt(text string) string {
	data := []byte(text)
	padded := padZero(data, 8)
	if len(padded) == 0 {
		padded = make([]byte, 8)
	}

	// 轮1：key[24..48] + iv
	m1 := des3CBCEncrypt(c.key[24:48], c.iv, padded)
	if m1 == nil {
		return ""
	}
	// 轮2：key[0..24] + iv
	m2 := des3CBCEncrypt(c.key[0:24], c.iv, m1)
	if m2 == nil {
		return ""
	}

	return hexEncode(m2)
}

func (c *desedeDoubleCBCAndroid) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) < 8 || len(data)%8 != 0 {
		return ""
	}

	// 逆轮1：key[0..24] + iv
	m1 := des3CBCDecrypt(c.key[0:24], c.iv, data)
	if m1 == nil {
		return ""
	}
	// 逆轮2：key[24..48] + iv
	pt := des3CBCDecrypt(c.key[24:48], c.iv, m1)
	if pt == nil {
		return ""
	}

	return string(stripTrailingZeros(pt))
}

// -----------------------------------------------------------------
// AD8BB5B0-0E72-4198-A362-96D52C1B7ED1 (Android six-layer DES-ECB)
// B306E770-B7D5-49F2-A574-BCE2C5C650ED (Linux DES 6-stage)
// -----------------------------------------------------------------

type desECBSix struct {
	key []byte
}

func NewDESECBSix(key []byte) Cipher {
	return &desECBSix{
		key: key,
	}
}

func (c *desECBSix) Encrypt(text string) string {
	data := []byte(text)
	padded := padZero(data, 8)
	if len(padded) == 0 {
		padded = make([]byte, 8)
	}

	b2, err := des.NewTripleDESCipher(c.key[24:48])
	if err != nil {
		return ""
	}
	b1, err := des.NewTripleDESCipher(c.key[0:24])
	if err != nil {
		return ""
	}

	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += 8 {
		t := make([]byte, 8)
		b2.Encrypt(t, padded[i:i+8])
		b1.Encrypt(out[i:i+8], t)
	}
	return hexEncode(out)
}

func (c *desECBSix) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) < 8 || len(data)%8 != 0 {
		return ""
	}

	b1, err := des.NewTripleDESCipher(c.key[0:24])
	if err != nil {
		return ""
	}
	b2, err := des.NewTripleDESCipher(c.key[24:48])
	if err != nil {
		return ""
	}

	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 8 {
		t := make([]byte, 8)
		b1.Decrypt(t, data[i:i+8])
		b2.Decrypt(out[i:i+8], t)
	}
	return string(stripTrailingZeros(out))
}

// -----------------------------------------------------------------
// 1A7343EC-7F9B-4570-BF58-16279A81116B (Linux DESede/CBC/Two-Layer)
// -----------------------------------------------------------------

type desedeCBCLinux struct {
	key1 []byte
	key2 []byte
	iv1  []byte
	iv2  []byte
}

func NewDESedeCBCLinux(key1, key2, iv1, iv2 []byte) Cipher {
	return &desedeCBCLinux{
		key1: key1,
		key2: key2,
		iv1:  iv1,
		iv2:  iv2,
	}
}

func (c *desedeCBCLinux) Encrypt(text string) string {
	data := []byte(text)
	padded := padZero(data, 8)
	if len(padded) == 0 {
		padded = make([]byte, 8)
	}

	// 阶段 1：key2 + iv2
	m1 := des3CBCEncrypt(c.key2, c.iv2, padded)
	if m1 == nil {
		return ""
	}
	// 阶段 2：key1 + iv1
	m2 := des3CBCEncrypt(c.key1, c.iv1, m1)
	if m2 == nil {
		return ""
	}

	return hexEncode(m2)
}

func (c *desedeCBCLinux) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) < 8 || len(data)%8 != 0 {
		return ""
	}

	// 逆阶段 1：key1 + iv1
	m1 := des3CBCDecrypt(c.key1, c.iv1, data)
	if m1 == nil {
		return ""
	}
	// 逆阶段 2：key2 + iv2
	pt := des3CBCDecrypt(c.key2, c.iv2, m1)
	if pt == nil {
		return ""
	}

	return string(stripTrailingZeros(pt))
}
