// Adapted from BadGhost520/ESurfingClient-CVersion win_zsm.c (Apache-2.0).
// Modified for Go: strict bounds checks, bounded decompression, no native-code execution.
package cipher

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/ulikunitz/xz/lzma"
	"io"
)

func NewWindowsZSMCipher(data []byte) (Cipher, error) {
	cs, err := NewWindowsZSMCiphers(data)
	if err != nil {
		return nil, err
	}
	return cs[0], nil
}

func NewWindowsZSMCiphers(data []byte) ([]Cipher, error) {
	if len(data) < 15 {
		return nil, fmt.Errorf("数据长度不足")
	}
	off := 3
	for i := 0; i < 2; i++ {
		if off >= len(data) {
			return nil, fmt.Errorf("容器头不完整")
		}
		n := int(data[off])
		off++
		if n > len(data)-off {
			return nil, fmt.Errorf("容器字符串越界")
		}
		off += n
	}
	if len(data)-off < 17 {
		return nil, fmt.Errorf("算法容器不完整")
	}
	props := data[off : off+5]
	packed := binary.LittleEndian.Uint32(data[off+5 : off+9])
	size := int(packed & 0x0fffffff)
	if packed>>28 != 2 || size <= 0 || size > 16*1024*1024 {
		return nil, fmt.Errorf("算法容器版本不兼容")
	}
	if binary.LittleEndian.Uint32(props[1:]) > 16*1024*1024 {
		return nil, fmt.Errorf("算法字典过大")
	}
	encrypted := append([]byte(nil), data[off+9:]...)
	if len(encrypted) == 0 || len(encrypted)%8 != 0 {
		return nil, fmt.Errorf("容器块长度无效")
	}
	key := []byte("|iKFMm;FZjI6oItGmvm536xR8MJ-5C89")
	for i := 0; i < len(encrypted); i += 8 {
		decryptWindowsTEA(key[:16], encrypted[i:i+8])
		decryptWindowsTEA(key[16:], encrypted[i:i+8])
	}
	pad := int(encrypted[len(encrypted)-1])
	if pad > len(encrypted) || pad > 8 {
		return nil, fmt.Errorf("容器填充无效")
	}
	header := make([]byte, 13)
	copy(header, props)
	binary.LittleEndian.PutUint64(header[5:], uint64(size))
	reader, err := lzma.NewReader(io.MultiReader(bytes.NewReader(header), bytes.NewReader(encrypted[:len(encrypted)-pad])))
	if err != nil {
		return nil, fmt.Errorf("无法初始化算法解压")
	}
	pe, err := io.ReadAll(io.LimitReader(reader, int64(size)+1))
	if err != nil || len(pe) != size {
		return nil, fmt.Errorf("算法解压失败")
	}
	k, iv, err := windowsKeyWindow(pe)
	if err != nil {
		return nil, err
	}
	switch {
	case len(k) == 32 && len(iv) == 16:
		return []Cipher{newWindowsAES(k, iv, true, false), newWindowsAES(k, iv, false, false), newWindowsAES(k, iv, true, true), NewAESDoubleCBCAndroid(k, iv), NewAESDoubleCBCAndroid(reverseKeyLayers(k, 16), iv)}, nil
	case len(k) == 32 && len(iv) == 0:
		return []Cipher{newWindowsAES(k, iv, true, false), newWindowsAES(k, iv, false, false), NewAESDoubleECBAndroid(k), NewAESDoubleECBAndroid(reverseKeyLayers(k, 16))}, nil
	case len(k) == 48 && len(iv) == 0:
		return []Cipher{NewTEATripleECBAndroid(k), NewTEATripleECBAndroid(reverseKeyLayers(k, 16)), NewDESECBSix(k)}, nil
	case len(k) == 48 && len(iv) == 8:
		return []Cipher{NewTEATripleCBCAndroid(k, iv), NewTEATripleCBCAndroid(reverseKeyLayers(k, 16), iv), NewDESedeDoubleCBCAndroid(k, iv), NewDESedeDoubleCBCAndroid(reverseKeyLayers(k, 24), iv)}, nil
	case len(k) == 16 && len(iv) == 0:
		return []Cipher{NewSM4VariantECB(k), NewSM4ECB(k)}, nil
	case len(k) == 16 && len(iv) == 16:
		return []Cipher{NewSM4VariantCBC(k, iv), NewSM4CBC(k, iv)}, nil
	default:
		return nil, fmt.Errorf("尚不支持的动态算法类型")
	}
}

func reverseKeyLayers(key []byte, n int) []byte {
	result := make([]byte, len(key))
	for i := 0; i < len(key); i += n {
		copy(result[i:i+n], key[len(key)-i-n:len(key)-i])
	}
	return result
}

func decryptWindowsTEA(key, block []byte) {
	var k [4]uint32
	for i := range k {
		k[i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	v0 := binary.LittleEndian.Uint32(block)
	v1 := binary.LittleEndian.Uint32(block[4:])
	sum := uint32(0xc6ef3720)
	for i := 0; i < 32; i++ {
		v1 -= ((v0 << 4) ^ (v0 >> 5)) + (k[(sum>>11)&3] + (v0 ^ sum))
		sum += 0x61c88647
		v0 -= k[sum&3] + (v1 ^ sum) + ((v1 << 4) ^ (v1 >> 5))
	}
	binary.LittleEndian.PutUint32(block, v0)
	binary.LittleEndian.PutUint32(block[4:], v1)
}

type peSection struct {
	va, vsize, raw, size int
	text                 bool
}

func windowsKeyWindow(pe []byte) ([]byte, []byte, error) {
	if len(pe) < 64 || string(pe[:2]) != "MZ" {
		return nil, nil, fmt.Errorf("算法不是 Windows 格式")
	}
	p := int(binary.LittleEndian.Uint32(pe[60:]))
	if p < 0 || p > len(pe)-24 || string(pe[p:p+4]) != "PE\x00\x00" {
		return nil, nil, fmt.Errorf("算法文件头无效")
	}
	n := int(binary.LittleEndian.Uint16(pe[p+6:]))
	opt := int(binary.LittleEndian.Uint16(pe[p+20:]))
	s := p + 24 + opt
	if opt < 32 || s > len(pe) || n > 16 || s+n*40 > len(pe) {
		return nil, nil, fmt.Errorf("算法节表无效")
	}
	base := binary.LittleEndian.Uint32(pe[p+52:])
	sections := []peSection{}
	for i := 0; i < n; i++ {
		o := s + i*40
		sec := peSection{va: int(binary.LittleEndian.Uint32(pe[o+12:])), vsize: int(binary.LittleEndian.Uint32(pe[o+8:])), raw: int(binary.LittleEndian.Uint32(pe[o+20:])), size: int(binary.LittleEndian.Uint32(pe[o+16:])), text: bytes.HasPrefix(pe[o:o+8], []byte(".text"))}
		if sec.raw < 0 || sec.raw > len(pe) || sec.size < 0 || sec.size > len(pe)-sec.raw {
			continue
		}
		sections = append(sections, sec)
	}
	for _, sec := range sections {
		if !sec.text {
			continue
		}
		t := pe[sec.raw : sec.raw+sec.size]
		for i := 0; i+5 <= len(t); i++ {
			if t[i] != 0xa0 {
				continue
			}
			addr := binary.LittleEndian.Uint32(t[i+1:])
			if addr < base {
				continue
			}
			rva := int(addr - base)
			for _, candidate := range sections {
				if rva < candidate.va || rva-candidate.va >= candidate.vsize {
					continue
				}
				offset := candidate.raw + rva - candidate.va
				w := offset - 255
				if w < 0 || w > len(pe)-256 {
					continue
				}
				b := pe[w : w+256]
				kl, il, ko := int(b[251]), int(b[249]), int(b[254])
				if (kl != 16 && kl != 24 && kl != 32 && kl != 48) || (il != 0 && il != 8 && il != 16) || ko+kl+il > 256 {
					continue
				}
				return append([]byte(nil), b[ko:ko+kl]...), append([]byte(nil), b[ko+kl:ko+kl+il]...), nil
			}
		}
	}
	return nil, nil, fmt.Errorf("未找到动态算法参数")
}
