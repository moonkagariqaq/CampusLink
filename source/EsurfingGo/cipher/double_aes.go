package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

// -----------------------------------------------------------------
// BB2EA626-590B-4C42-82BE-E052FCBBB88E (Android double AES-CBC)
// -----------------------------------------------------------------

type aesDoubleCBCAndroid struct {
	key []byte
	iv  []byte
}

func NewAESDoubleCBCAndroid(key, iv []byte) Cipher {
	return &aesDoubleCBCAndroid{
		key: key,
		iv:  iv,
	}
}

func aesLayerCBCEncrypt(key16 []byte, iv []byte, data []byte) []byte {
	block, err := aes.NewCipher(key16)
	if err != nil {
		return nil
	}
	padded := padZero(data, 16)
	if len(padded) == 0 {
		padded = make([]byte, 16)
	}

	out := make([]byte, 16+len(padded))
	copy(out[:16], iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out[16:], padded)
	return out
}

func aesLayerCBCDecrypt(key16 []byte, data []byte) []byte {
	if len(data) < 32 || len(data)%16 != 0 {
		return nil
	}
	block, err := aes.NewCipher(key16)
	if err != nil {
		return nil
	}

	iv := data[:16]
	ciphertext := data[16:]
	out := make([]byte, len(ciphertext))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(out, ciphertext)
	return out
}

func (c *aesDoubleCBCAndroid) Encrypt(text string) string {
	data := []byte(text)
	m1 := aesLayerCBCEncrypt(c.key[:16], c.iv, data)
	if m1 == nil {
		return ""
	}
	m2 := aesLayerCBCEncrypt(c.key[16:32], c.iv, m1)
	if m2 == nil {
		return ""
	}
	return hexEncode(m2)
}

func (c *aesDoubleCBCAndroid) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) < 32 || len(data)%16 != 0 {
		return ""
	}
	m1 := aesLayerCBCDecrypt(c.key[16:32], data)
	if m1 == nil {
		return ""
	}
	pt := aesLayerCBCDecrypt(c.key[:16], m1)
	if pt == nil {
		return ""
	}
	return string(stripTrailingZeros(pt))
}

// -----------------------------------------------------------------
// DEABB8C8-A2BC-48CA-8ED0-8CDF1BD62F61 (Android double AES-ECB)
// -----------------------------------------------------------------

type aesDoubleECBAndroid struct {
	key []byte
}

func NewAESDoubleECBAndroid(key []byte) Cipher {
	return &aesDoubleECBAndroid{
		key: key,
	}
}

func aesECBEncrypt(key16 []byte, data []byte) []byte {
	block, err := aes.NewCipher(key16)
	if err != nil {
		return nil
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		block.Encrypt(out[i:i+16], data[i:i+16])
	}
	return out
}

func aesECBDecrypt(key16 []byte, data []byte) []byte {
	block, err := aes.NewCipher(key16)
	if err != nil {
		return nil
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		block.Decrypt(out[i:i+16], data[i:i+16])
	}
	return out
}

func (c *aesDoubleECBAndroid) Encrypt(text string) string {
	data := []byte(text)
	padded := padZero(data, 16)
	if len(padded) == 0 {
		padded = make([]byte, 16)
	}

	m1 := aesECBEncrypt(c.key[:16], padded)
	if m1 == nil {
		return ""
	}
	m2 := aesECBEncrypt(c.key[16:32], m1)
	if m2 == nil {
		return ""
	}
	return hexEncode(m2)
}

func (c *aesDoubleECBAndroid) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) < 16 || len(data)%16 != 0 {
		return ""
	}

	m1 := aesECBDecrypt(c.key[16:32], data)
	if m1 == nil {
		return ""
	}
	pt := aesECBDecrypt(c.key[:16], m1)
	if pt == nil {
		return ""
	}
	return string(stripTrailingZeros(pt))
}

// -----------------------------------------------------------------
// 45433DCF-9ECA-4BE5-83F2-F92BA0B4F291 (Linux AES-CBC Two-Layer)
// -----------------------------------------------------------------

type aesCBCLinux struct {
	key1 []byte
	key2 []byte
}

func NewAESCBCLinux(key1, key2 []byte) Cipher {
	return &aesCBCLinux{
		key1: key1,
		key2: key2,
	}
}

func (c *aesCBCLinux) Encrypt(text string) string {
	data := []byte(text)
	padded := padZero(data, 16)
	if len(padded) == 0 {
		padded = make([]byte, 16)
	}

	zeroIV := make([]byte, 16)

	// Stage 1
	b1, err := aes.NewCipher(c.key1)
	if err != nil {
		return ""
	}
	stage1 := make([]byte, 16+len(padded))
	copy(stage1[:16], zeroIV)
	m1 := cipher.NewCBCEncrypter(b1, zeroIV)
	m1.CryptBlocks(stage1[16:], padded)

	// Stage 2
	b2, err := aes.NewCipher(c.key2)
	if err != nil {
		return ""
	}
	stage2 := make([]byte, 16+len(stage1))
	copy(stage2[:16], zeroIV)
	m2 := cipher.NewCBCEncrypter(b2, zeroIV)
	m2.CryptBlocks(stage2[16:], stage1)

	return hexEncode(stage2)
}

func (c *aesCBCLinux) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) < 32 || len(data)%16 != 0 {
		return ""
	}

	iv2 := data[:16]
	c2 := data[16:]
	b2, err := aes.NewCipher(c.key2)
	if err != nil {
		return ""
	}
	stage1 := make([]byte, len(c2))
	m2 := cipher.NewCBCDecrypter(b2, iv2)
	m2.CryptBlocks(stage1, c2)

	if len(stage1) < 32 {
		return ""
	}

	iv1 := stage1[:16]
	c1 := stage1[16:]
	b1, err := aes.NewCipher(c.key1)
	if err != nil {
		return ""
	}
	out := make([]byte, len(c1))
	m1 := cipher.NewCBCDecrypter(b1, iv1)
	m1.CryptBlocks(out, c1)

	return string(stripTrailingZeros(out))
}

// -----------------------------------------------------------------
// 4BA5496A-2123-46A7-85F2-35956EA7BE39 (Linux AES-ECB Two-Layer)
// -----------------------------------------------------------------

type aesECBLinux struct {
	key1 []byte
	key2 []byte
}

func NewAESECBLinux(key1, key2 []byte) Cipher {
	return &aesECBLinux{
		key1: key1,
		key2: key2,
	}
}

func (c *aesECBLinux) Encrypt(text string) string {
	data := []byte(text)
	padded := padZero(data, 16)
	if len(padded) == 0 {
		padded = make([]byte, 16)
	}

	b1, err := aes.NewCipher(c.key1)
	if err != nil {
		return ""
	}
	b2, err := aes.NewCipher(c.key2)
	if err != nil {
		return ""
	}

	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += 16 {
		tmp := make([]byte, 16)
		b2.Encrypt(tmp, padded[i:i+16])
		b1.Encrypt(out[i:i+16], tmp)
	}
	return hexEncode(out)
}

func (c *aesECBLinux) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) < 16 || len(data)%16 != 0 {
		return ""
	}

	b1, err := aes.NewCipher(c.key1)
	if err != nil {
		return ""
	}
	b2, err := aes.NewCipher(c.key2)
	if err != nil {
		return ""
	}

	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		tmp := make([]byte, 16)
		b1.Decrypt(tmp, data[i:i+16])
		b2.Decrypt(out[i:i+16], tmp)
	}
	return string(stripTrailingZeros(out))
}

// 保证使用 bytes 包避免 unused warning
var _ = bytes.TrimRight
