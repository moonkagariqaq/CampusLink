package main

import (
	"esurfing/cipher"
	"fmt"
	"log"
	"strings"
	"sync"
)

// Session manages the encryption cipher for the current connection.
type Session struct {
	mu             sync.RWMutex
	initialized    bool
	cipher         cipher.Cipher
	candidates     []cipher.Cipher
	candidateIndex int
	algoID         string
}

func NewSession() *Session {
	return &Session{}
}

// Initialize parses the ZSM response bytes and initializes the cipher.
func (s *Session) Initialize(zsm []byte) {
	log.Println("Initializing Session...")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initialized = s.load(zsm)
}

func isUUIDText(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

func readPascalString(data []byte, offset *int) (string, bool) {
	if *offset >= len(data) {
		return "", false
	}
	strLen := int(data[*offset])
	*offset++
	if *offset+strLen > len(data) {
		return "", false
	}
	str := string(data[*offset : *offset+strLen])
	*offset += strLen
	return str, true
}

// extractAlgoIDFromZSM 提取 ZSM 中的算法 UUID，与 BadGhost520/ESurfingClient-CVersion 保持一致
func extractAlgoIDFromZSM(zsm []byte) (string, bool) {
	if len(zsm) < 5 {
		return "", false
	}

	// 1. 尝试从 offset = 3 解析两个 Pascal string
	offset := 3
	str1, ok1 := readPascalString(zsm, &offset)
	if ok1 {
		str2, ok2 := readPascalString(zsm, &offset)
		if ok2 && isUUIDText(str2) {
			return strings.ToUpper(str2), true
		}
		if isUUIDText(str1) {
			return strings.ToUpper(str1), true
		}
	}

	// 2. 回退机制：从末尾去除空白与 null 字符，检查尾部 36 字符是否为 UUID
	end := len(zsm)
	for end > 0 {
		c := zsm[end-1]
		if c == '\n' || c == '\r' || c == '\x00' || c == ' ' || c == '\t' {
			end--
			continue
		}
		break
	}
	if end >= 36 {
		tail := string(zsm[end-36 : end])
		if isUUIDText(tail) {
			return strings.ToUpper(tail), true
		}
	}

	return "", false
}

func (s *Session) load(zsm []byte) bool {
	if len(zsm) == 0 {
		log.Printf("[Session] 无效的 ZSM 数据")
		return false
	}

	hexLen := min(len(zsm), 200)
	log.Printf("[Session] ZSM 长度: %d, 前 %d 字节 Hex: %X", len(zsm), hexLen, zsm[:hexLen])

	algoID, ok := extractAlgoIDFromZSM(zsm)
	if !ok {
		report("diagnostic", fmt.Sprintf("认证算法数据：%d 字节，格式头 %X", len(zsm), zsm[:min(len(zsm), 8)]))
		log.Printf("[Session] 无法从 ZSM 中提取 Algo-ID")
		return false
	}
	log.Printf("[Session] 成功提取 Algo-ID: %s", algoID)
	report("algorithm", "服务器算法标识："+algoID)

	c, err := cipher.NewCipher(algoID)
	s.candidates = nil
	s.candidateIndex = 0
	if err != nil {
		s.candidates, err = cipher.NewWindowsZSMCiphers(zsm)
		if err != nil {
			report("error", "Windows 动态算法解析失败："+err.Error())
			return false
		}
		c = s.candidates[0]
	}
	s.cipher = c
	report("algorithm", fmt.Sprintf("已加载动态算法：%T", c))
	s.algoID = algoID
	return true
}

func (s *Session) NextCipher() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.candidateIndex+1 >= len(s.candidates) {
		return false
	}
	s.candidateIndex++
	s.cipher = s.candidates[s.candidateIndex]
	report("status", "正在校验 Windows 算法的层次顺序；尚未提交密码。")
	return true
}

func (s *Session) IsInitialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.initialized
}

func (s *Session) Encrypt(text string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cipher == nil {
		return "", fmt.Errorf("cipher not initialized")
	}
	return s.cipher.Encrypt(text), nil
}

func (s *Session) Decrypt(hexStr string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cipher == nil {
		return "", fmt.Errorf("cipher not initialized")
	}
	return s.cipher.Decrypt(hexStr), nil
}

func (s *Session) GetAlgoID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.algoID
}

func (s *Session) Free() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initialized = false
	s.cipher = nil
}
