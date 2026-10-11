package cipher

import (
	"testing"
)

// TestAllCiphersRoundTrip verifies encrypt/decrypt round-trip for all cipher implementations.
func TestOldAndroidRoundTrip(t *testing.T) {
	testRoundTrip(t, "AESCBC", NewAESCBC(KeyCAFBCBAD_Key1, KeyCAFBCBAD_Key2, KeyCAFBCBAD_IV))
	testRoundTrip(t, "AESECB", NewAESECB(KeyA474B1C2_Key1, KeyA474B1C2_Key2))
	testRoundTrip(t, "DESedeCBC", NewDESedeCBC(Key5BFBA864_Key1, Key5BFBA864_Key2, Key5BFBA864_IV))
	testRoundTrip(t, "DESedeECB", NewDESedeECB(Key6E0B65FF_Key1, Key6E0B65FF_Key2))
	testRoundTrip(t, "SM4CBC", NewSM4CBC(KeyF3974434_Key, KeyF3974434_IV))
	testRoundTrip(t, "SM4ECB", NewSM4ECB(KeyED382482_Key))
	testRoundTrip(t, "ZUC", NewZUC(KeyB809531F_Key, KeyB809531F_IV))
	testRoundTrip(t, "ModXTEA", NewModXTEA(KeyB3047D4E_Key1, KeyB3047D4E_Key2, KeyB3047D4E_Key3))
	testRoundTrip(t, "ModXTEAXTEAIV", NewModXTEAXTEAIV(KeyC32C68F9_Key1, KeyC32C68F9_Key2, KeyC32C68F9_Key3, KeyC32C68F9_IV))
}

func TestNewAndroidRoundTrip(t *testing.T) {
	testRoundTrip(t, "Snow3gVariant", NewSnow3gVariant(Key07E824B2_Key, Key07E824B2_IV))
	testRoundTrip(t, "TEATripleECBAndroid", NewTEATripleECBAndroid(Key319FC5AB_Key))
	testRoundTrip(t, "SM4VariantCBC", NewSM4VariantCBC(KeyD6544CFE_Key, KeyD6544CFE_IV))
	testRoundTrip(t, "SM4VariantECB", NewSM4VariantECB(KeyD755A536_Key))
	testRoundTrip(t, "AESDoubleCBCAndroid", NewAESDoubleCBCAndroid(KeyBB2EA626_Key, KeyBB2EA626_IV))
	testRoundTrip(t, "AESDoubleECBAndroid", NewAESDoubleECBAndroid(KeyDEABB8C8_Key))
	testRoundTrip(t, "DESedeDoubleCBCAndroid", NewDESedeDoubleCBCAndroid(Key9ABF4D29_Key, Key9ABF4D29_IV))
	testRoundTrip(t, "DESECBSixAndroid", NewDESECBSix(KeyAD8BB5B0_Key))
	testRoundTrip(t, "TEATripleCBCAndroid", NewTEATripleCBCAndroid(Key35101415_Key, Key35101415_IV))
}

func TestLinuxRoundTrip(t *testing.T) {
	t.Run("DESedeCBCLinux", func(t *testing.T) {
		testRoundTrip(t, "DESedeCBCLinux", NewDESedeCBCLinux(Key1A7343EC_Key1, Key1A7343EC_Key2, Key1A7343EC_IV1, Key1A7343EC_IV2))
	})
	t.Run("AESECBLinux", func(t *testing.T) {
		testRoundTrip(t, "AESECBLinux", NewAESECBLinux(Key4BA5496A_Key1, Key4BA5496A_Key2))
	})
	t.Run("AESCBCLinux", func(t *testing.T) {
		testRoundTrip(t, "AESCBCLinux", NewAESCBCLinux(Key45433DCF_Key1, Key45433DCF_Key2))
	})
	t.Run("ModXTEALinux", func(t *testing.T) {
		testRoundTrip(t, "ModXTEALinux", NewModXTEALinux(Key60639D8B_Key1, Key60639D8B_Key2, Key60639D8B_Key3))
	})
	t.Run("AB6C8Linux", func(t *testing.T) {
		testRoundTrip(t, "AB6C8Linux", NewAB6C8Linux(KeyAB6C8EBE_Key1, KeyAB6C8EBE_Key2, KeyAB6C8EBE_Key3, KeyAB6C8EBE_IV))
	})
	t.Run("DESECBSixLinux", func(t *testing.T) {
		b306Key := make([]byte, 48)
		copy(b306Key[0:8], KeyB306E770_Key1)
		copy(b306Key[8:16], KeyB306E770_Key2)
		copy(b306Key[16:24], KeyB306E770_Key3)
		copy(b306Key[24:32], KeyB306E770_Key4)
		copy(b306Key[32:40], KeyB306E770_Key5)
		copy(b306Key[40:48], KeyB306E770_Key6)
		testRoundTrip(t, "DESECBSixLinux", NewDESECBSix(b306Key))
	})
}

func testRoundTrip(t *testing.T, name string, c Cipher) {
	testCases := []string{
		"hello",
		"test message with more data",
		`<?xml version="1.0" encoding="utf-8"?><request><user-agent>CCTP/android11_64/2104</user-agent></request>`,
		"short",
		"a",
		"exactly16bytess!",
		"中文内容测试",
	}

	for _, original := range testCases {
		encrypted := c.Encrypt(original)
		if encrypted == "" {
			t.Errorf("[%s] Encrypt(%q) returned empty string", name, original)
			continue
		}
		if encrypted == original {
			t.Errorf("[%s] Encrypt(%q) returned plaintext", name, original)
			continue
		}
		decrypted := c.Decrypt(encrypted)
		if decrypted != original {
			t.Errorf("[%s] Round-trip failed for %q:\n  encrypted: %s\n  decrypted: %q", name, original, encrypted, decrypted)
		}
	}
}

// TestCipherFactory tests the factory function with all 24 algorithms.
func TestCipherFactory(t *testing.T) {
	algoIDs := []string{
		// 9 旧版 Android
		"CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E",
		"A474B1C2-3DE0-4EA2-8C5F-7093409CE6C4",
		"5BFBA864-BBA9-42DB-8EAD-49B5F412BD81",
		"6E0B65FF-0B5B-459C-8FCE-EC7F2BEA9FF5",
		"B809531F-0007-4B5B-923B-4BD560398113",
		"F3974434-C0DD-4C20-9E87-DDB6814A1C48",
		"ED382482-F72C-4C41-A76D-28EEA0F1F2AF",
		"B3047D4E-67DF-4864-A6A5-DF9B9E525C79",
		"C32C68F9-CA81-4260-A329-BBAFD1A9CCD1",
		// 9 最新 Android
		"07E824B2-9E5C-4D1B-BBB0-5E07C251E4AA",
		"319FC5AB-EC0E-46B9-A252-2285F9DAE813",
		"D6544CFE-F2DE-459B-9B77-0F2B367EF169",
		"D755A536-B551-468C-BD87-322182B223D4",
		"BB2EA626-590B-4C42-82BE-E052FCBBB88E",
		"DEABB8C8-A2BC-48CA-8ED0-8CDF1BD62F61",
		"9ABF4D29-34DB-4CE9-BB8C-7E371D637758",
		"AD8BB5B0-0E72-4198-A362-96D52C1B7ED1",
		"35101415-A20F-4DFE-B00B-0B4F3B2F8C66",
		// 6 Linux
		"1A7343EC-7F9B-4570-BF58-16279A81116B",
		"4BA5496A-2123-46A7-85F2-35956EA7BE39",
		"45433DCF-9ECA-4BE5-83F2-F92BA0B4F291",
		"60639D8B-272E-4A4D-976E-AA270987A169",
		"AB6C8EBE-B8F8-4C08-8222-69A3B5E86A91",
		"B306E770-B7D5-49F2-A574-BCE2C5C650ED",
	}

	for _, id := range algoIDs {
		c, err := NewCipher(id)
		if err != nil {
			t.Errorf("NewCipher(%s) failed: %v", id, err)
			continue
		}
		original := "test data for " + id
		encrypted := c.Encrypt(original)
		decrypted := c.Decrypt(encrypted)
		if decrypted != original {
			t.Errorf("Factory round-trip failed for %s: got %q, want %q", id, decrypted, original)
		}
	}

	// 验证小写输入能否成功被规范化为大写并解析
	_, err := NewCipher("07e824b2-9e5c-4d1b-bbb0-5e07c251e4aa")
	if err != nil {
		t.Errorf("NewCipher(lowercase) should succeed, got error: %v", err)
	}

	// 未知算法应当报错
	_, err = NewCipher("unknown-id")
	if err == nil {
		t.Error("NewCipher(unknown) should return error")
	}
}

// TestHexEncodeDecode tests hex encoding helpers.
func TestHexEncodeDecode(t *testing.T) {
	data := []byte{0x01, 0xAB, 0xFF, 0x00}
	encoded := hexEncode(data)
	if encoded != "01ABFF00" {
		t.Errorf("hexEncode = %s, want 01ABFF00", encoded)
	}
	decoded, err := hexDecode(encoded)
	if err != nil {
		t.Errorf("hexDecode error: %v", err)
	}
	for i, b := range decoded {
		if b != data[i] {
			t.Errorf("hexDecode[%d] = %d, want %d", i, b, data[i])
		}
	}
}

// TestStripTrailingZeros tests zero-padding removal.
func TestStripTrailingZeros(t *testing.T) {
	tests := []struct {
		input    []byte
		expected []byte
	}{
		{[]byte{1, 2, 3, 0, 0, 0}, []byte{1, 2, 3}},
		{[]byte{1, 2, 3}, []byte{1, 2, 3}},
		{[]byte{0, 0}, []byte{}},
		{[]byte{}, []byte{}},
	}
	for _, tc := range tests {
		result := stripTrailingZeros(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("stripTrailingZeros(%v) = %v, want %v", tc.input, result, tc.expected)
		}
	}
}
