package main

import (
	"testing"
)

func TestExtractAlgoIDFromZSM(t *testing.T) {
	// Case 1: Standard Pascal strings [3 bytes header, len1, str1, len2, str2(UUID)]
	uuid := "07E824B2-9E5C-4D1B-BBB0-5E07C251E4AA"
	str1 := "module_name_or_salt"
	data := []byte{0x00, 0x01, 0x02, byte(len(str1))}
	data = append(data, []byte(str1)...)
	data = append(data, byte(len(uuid)))
	data = append(data, []byte(uuid)...)
	data = append(data, []byte("extra data after")...)

	algoID, ok := extractAlgoIDFromZSM(data)
	if !ok || algoID != uuid {
		t.Fatalf("Case 1 failed: got %q, %v, want %q, true", algoID, ok, uuid)
	}

	// Case 2: Lowercase UUID normalized to uppercase
	lowerUUID := "07e824b2-9e5c-4d1b-bbb0-5e07c251e4aa"
	data2 := []byte{0x00, 0x00, 0x00, byte(len(str1))}
	data2 = append(data2, []byte(str1)...)
	data2 = append(data2, byte(len(lowerUUID)))
	data2 = append(data2, []byte(lowerUUID)...)

	algoID, ok = extractAlgoIDFromZSM(data2)
	if !ok || algoID != uuid {
		t.Fatalf("Case 2 failed: got %q, %v, want %q, true", algoID, ok, uuid)
	}

	// Case 3: Fallback tail UUID
	data3 := []byte("prefix garbage data that fails pascal string parsing ")
	data3 = append(data3, []byte(lowerUUID)...)
	data3 = append(data3, []byte("\r\n\x00")...)

	algoID, ok = extractAlgoIDFromZSM(data3)
	if !ok || algoID != uuid {
		t.Fatalf("Case 3 failed: got %q, %v, want %q, true", algoID, ok, uuid)
	}
}
