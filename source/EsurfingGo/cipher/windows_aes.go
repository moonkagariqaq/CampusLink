package cipher

import (
	"bytes"
	"crypto/aes"
	stdcipher "crypto/cipher"
)

// Native Windows modules may use AES-256 rather than Android's double AES-128.
type windowsAES struct {
	key, iv       []byte
	pkcs7, prefix bool
}

func newWindowsAES(key, iv []byte, pkcs7, prefix bool) Cipher {
	return &windowsAES{append([]byte(nil), key...), append([]byte(nil), iv...), pkcs7, prefix}
}
func (c *windowsAES) Encrypt(text string) string {
	data := []byte(text)
	if c.pkcs7 {
		pad := 16 - len(data)%16
		data = append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
	} else {
		data = padZero(data, 16)
	}
	if len(data) == 0 {
		return ""
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return ""
	}
	out := make([]byte, len(data))
	if len(c.iv) == 16 {
		stdcipher.NewCBCEncrypter(block, c.iv).CryptBlocks(out, data)
	} else {
		for i := 0; i < len(data); i += 16 {
			block.Encrypt(out[i:i+16], data[i:i+16])
		}
	}
	if c.prefix && len(c.iv) == 16 {
		out = append(append([]byte(nil), c.iv...), out...)
	}
	return hexEncode(out)
}
func (c *windowsAES) Decrypt(text string) string {
	data, err := hexDecode(text)
	if err != nil || len(data) == 0 || len(data)%16 != 0 {
		return ""
	}
	iv := c.iv
	if c.prefix && len(iv) == 16 {
		if len(data) < 32 {
			return ""
		}
		iv = data[:16]
		data = data[16:]
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return ""
	}
	out := make([]byte, len(data))
	if len(iv) == 16 {
		stdcipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	} else {
		for i := 0; i < len(data); i += 16 {
			block.Decrypt(out[i:i+16], data[i:i+16])
		}
	}
	if c.pkcs7 {
		pad := int(out[len(out)-1])
		if pad < 1 || pad > 16 || !bytes.Equal(out[len(out)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
			return ""
		}
		out = out[:len(out)-pad]
	} else {
		out = stripTrailingZeros(out)
	}
	return string(out)
}
