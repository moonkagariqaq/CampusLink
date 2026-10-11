package cipher

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// SM4 变体常数定义
var sm4VariantFK = [4]uint32{0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC}

var sm4VariantCK = [32]uint32{
	0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
	0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249, 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
	0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229, 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
	0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209, 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
}

var sm4VariantS = [256]byte{
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
}

// sm4VariantKeySched 计算 32 轮子密钥，mode=1 为加密，mode=0 为解密
func sm4VariantKeySched(key []byte, mode int) [32]uint32 {
	var rk [32]uint32
	var K [4]uint32
	for i := 0; i < 4; i++ {
		K[i] = binary.BigEndian.Uint32(key[i*4:(i+1)*4]) ^ sm4VariantFK[i]
	}
	for i := 0; i < 32; i++ {
		t := K[1] ^ K[2] ^ K[3] ^ sm4VariantCK[i]
		s0 := uint32(sm4VariantS[t>>24])
		s1 := uint32(sm4VariantS[(t>>16)&0xFF])
		s2 := uint32(sm4VariantS[(t>>8)&0xFF])
		s3 := uint32(sm4VariantS[t&0xFF])
		w4 := (s0 << 24) | (s1 << 16)
		w1 := w4 | (s2 << 8)
		B := w1 | s3
		e1 := ((B << 13) | (w4 >> 19)) & 0xFFFFFFFF
		e2 := ((B << 23) | (w1 >> 9)) & 0xFFFFFFFF
		rk[i] = B ^ K[0] ^ e1 ^ e2
		K[0] = K[1]
		K[1] = K[2]
		K[2] = K[3]
		K[3] = rk[i]
	}
	if mode == 0 {
		for i := 0; i < 16; i++ {
			rk[i], rk[31-i] = rk[31-i], rk[i]
		}
	}
	return rk
}

// sm4VariantBlock 单个 16 字节块加密/解密
func sm4VariantBlock(rk [32]uint32, in []byte, out []byte) {
	X := [4]uint32{
		binary.BigEndian.Uint32(in[0:4]),
		binary.BigEndian.Uint32(in[4:8]),
		binary.BigEndian.Uint32(in[8:12]),
		binary.BigEndian.Uint32(in[12:16]),
	}
	var store [32]uint32
	for i := 0; i < 32; i++ {
		t := X[1] ^ X[2] ^ X[3] ^ rk[i]
		s0 := uint32(sm4VariantS[t>>24])
		s1 := uint32(sm4VariantS[(t>>16)&0xFF])
		s2 := uint32(sm4VariantS[(t>>8)&0xFF])
		s3 := uint32(sm4VariantS[t&0xFF])
		w4 := (s0 << 24) | (s1 << 16)
		w1 := w4 | (s2 << 8)
		B := w1 | s3
		e0 := (s0 >> 6) | ((B & 0x3FFFFFFF) << 2)
		e1 := ((B << 24) | (w1 >> 8)) & 0xFFFFFFFF
		e2 := ((B << 10) | (w4 >> 22)) & 0xFFFFFFFF
		e3 := ((B << 18) | (w1 >> 14)) & 0xFFFFFFFF
		nx := B ^ X[0] ^ e1 ^ e0 ^ e2 ^ e3
		store[i] = nx
		X[0] = X[1]
		X[1] = X[2]
		X[2] = X[3]
		X[3] = nx
	}
	binary.BigEndian.PutUint32(out[0:4], store[31])
	binary.BigEndian.PutUint32(out[4:8], store[30])
	binary.BigEndian.PutUint32(out[8:12], store[29])
	binary.BigEndian.PutUint32(out[12:16], store[28])
}

// padPKCS7 对数据进行 PKCS#7 填充
func padPKCS7(data []byte, blockSize int) []byte {
	pad := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+pad)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	return padded
}

// unpadPKCS7 去除 PKCS#7 填充
func unpadPKCS7(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid data length for pkcs7 unpadding")
	}
	pad := int(data[len(data)-1])
	if pad < 1 || pad > blockSize {
		return nil, errors.New("invalid padding value")
	}
	for i := len(data) - pad; i < len(data); i++ {
		if int(data[i]) != pad {
			return nil, errors.New("invalid padding bytes")
		}
	}
	return data[:len(data)-pad], nil
}

// -----------------------------------------------------------------
// D6544CFE-F2DE-459B-9B77-0F2B367EF169 (SM4-variant CBC)
// -----------------------------------------------------------------

type sm4VariantCBC struct {
	key []byte
	iv  []byte
}

func NewSM4VariantCBC(key, iv []byte) Cipher {
	return &sm4VariantCBC{
		key: key,
		iv:  iv,
	}
}

func (c *sm4VariantCBC) Encrypt(text string) string {
	data := []byte(text)
	padded := padPKCS7(data, 16)
	rk := sm4VariantKeySched(c.key, 1)

	out := make([]byte, len(padded))
	prev := make([]byte, 16)
	copy(prev, c.iv)

	for off := 0; off < len(padded); off += 16 {
		t := make([]byte, 16)
		for i := 0; i < 16; i++ {
			t[i] = padded[off+i] ^ prev[i]
		}
		sm4VariantBlock(rk, t, out[off:off+16])
		copy(prev, out[off:off+16])
	}

	return hexEncode(out)
}

func (c *sm4VariantCBC) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) < 16 || len(data)%16 != 0 {
		return ""
	}

	rk := sm4VariantKeySched(c.key, 0)
	buf := make([]byte, len(data))
	prev := make([]byte, 16)
	copy(prev, c.iv)

	for off := 0; off < len(data); off += 16 {
		t := make([]byte, 16)
		copy(t, data[off:off+16])
		dec := make([]byte, 16)
		sm4VariantBlock(rk, t, dec)
		for i := 0; i < 16; i++ {
			buf[off+i] = dec[i] ^ prev[i]
		}
		copy(prev, t)
	}

	unpadded, err := unpadPKCS7(buf, 16)
	if err != nil {
		return ""
	}
	return string(bytes.TrimRight(unpadded, "\x00"))
}

// -----------------------------------------------------------------
// D755A536-B551-468C-BD87-322182B223D4 (SM4-variant ECB)
// -----------------------------------------------------------------

type sm4VariantECB struct {
	key []byte
}

func NewSM4VariantECB(key []byte) Cipher {
	return &sm4VariantECB{
		key: key,
	}
}

func (c *sm4VariantECB) Encrypt(text string) string {
	data := []byte(text)
	padded := padPKCS7(data, 16)
	rk := sm4VariantKeySched(c.key, 1)

	out := make([]byte, len(padded))
	for off := 0; off < len(padded); off += 16 {
		sm4VariantBlock(rk, padded[off:off+16], out[off:off+16])
	}

	return hexEncode(out)
}

func (c *sm4VariantECB) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) < 16 || len(data)%16 != 0 {
		return ""
	}

	rk := sm4VariantKeySched(c.key, 0)
	buf := make([]byte, len(data))
	for off := 0; off < len(data); off += 16 {
		sm4VariantBlock(rk, data[off:off+16], buf[off:off+16])
	}

	unpadded, err := unpadPKCS7(buf, 16)
	if err != nil {
		return ""
	}
	return string(bytes.TrimRight(unpadded, "\x00"))
}
