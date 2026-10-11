package cipher

import (
	"fmt"
	"strings"
)

// Cipher defines the encryption/decryption interface.
type Cipher interface {
	Encrypt(text string) string
	Decrypt(hex string) string
}

// NewCipher creates a cipher instance for the given algorithm ID.
func NewCipher(algoID string) (Cipher, error) {
	upperAlgoID := strings.ToUpper(algoID)
	switch upperAlgoID {
	// -----------------------------------------------------------------
	// 旧版 Android 算法 (Android old - 已弃用但保持向下兼容)
	// -----------------------------------------------------------------
	case "CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E":
		return NewAESCBC(
			KeyCAFBCBAD_Key1, KeyCAFBCBAD_Key2, KeyCAFBCBAD_IV,
		), nil
	case "A474B1C2-3DE0-4EA2-8C5F-7093409CE6C4":
		return NewAESECB(
			KeyA474B1C2_Key1, KeyA474B1C2_Key2,
		), nil
	case "5BFBA864-BBA9-42DB-8EAD-49B5F412BD81":
		return NewDESedeCBC(
			Key5BFBA864_Key1, Key5BFBA864_Key2, Key5BFBA864_IV,
		), nil
	case "6E0B65FF-0B5B-459C-8FCE-EC7F2BEA9FF5":
		return NewDESedeECB(
			Key6E0B65FF_Key1, Key6E0B65FF_Key2,
		), nil
	case "B809531F-0007-4B5B-923B-4BD560398113":
		return NewZUC(
			KeyB809531F_Key, KeyB809531F_IV,
		), nil
	case "F3974434-C0DD-4C20-9E87-DDB6814A1C48":
		return NewSM4CBC(
			KeyF3974434_Key, KeyF3974434_IV,
		), nil
	case "ED382482-F72C-4C41-A76D-28EEA0F1F2AF":
		return NewSM4ECB(
			KeyED382482_Key,
		), nil
	case "B3047D4E-67DF-4864-A6A5-DF9B9E525C79":
		return NewModXTEA(
			KeyB3047D4E_Key1, KeyB3047D4E_Key2, KeyB3047D4E_Key3,
		), nil
	case "C32C68F9-CA81-4260-A329-BBAFD1A9CCD1":
		return NewModXTEAXTEAIV(
			KeyC32C68F9_Key1, KeyC32C68F9_Key2, KeyC32C68F9_Key3, KeyC32C68F9_IV,
		), nil

	// -----------------------------------------------------------------
	// 最新 Android 算法 (Android new)
	// -----------------------------------------------------------------
	case "07E824B2-9E5C-4D1B-BBB0-5E07C251E4AA":
		return NewSnow3gVariant(Key07E824B2_Key, Key07E824B2_IV), nil
	case "319FC5AB-EC0E-46B9-A252-2285F9DAE813":
		return NewTEATripleECBAndroid(Key319FC5AB_Key), nil
	case "D6544CFE-F2DE-459B-9B77-0F2B367EF169":
		return NewSM4VariantCBC(KeyD6544CFE_Key, KeyD6544CFE_IV), nil
	case "D755A536-B551-468C-BD87-322182B223D4":
		return NewSM4VariantECB(KeyD755A536_Key), nil
	case "BB2EA626-590B-4C42-82BE-E052FCBBB88E":
		return NewAESDoubleCBCAndroid(KeyBB2EA626_Key, KeyBB2EA626_IV), nil
	case "DEABB8C8-A2BC-48CA-8ED0-8CDF1BD62F61":
		return NewAESDoubleECBAndroid(KeyDEABB8C8_Key), nil
	case "9ABF4D29-34DB-4CE9-BB8C-7E371D637758":
		return NewDESedeDoubleCBCAndroid(Key9ABF4D29_Key, Key9ABF4D29_IV), nil
	case "AD8BB5B0-0E72-4198-A362-96D52C1B7ED1":
		return NewDESECBSix(KeyAD8BB5B0_Key), nil
	case "35101415-A20F-4DFE-B00B-0B4F3B2F8C66":
		return NewTEATripleCBCAndroid(Key35101415_Key, Key35101415_IV), nil

	// -----------------------------------------------------------------
	// Linux 平台算法 (Linux)
	// -----------------------------------------------------------------
	case "1A7343EC-7F9B-4570-BF58-16279A81116B":
		return NewDESedeCBCLinux(Key1A7343EC_Key1, Key1A7343EC_Key2, Key1A7343EC_IV1, Key1A7343EC_IV2), nil
	case "4BA5496A-2123-46A7-85F2-35956EA7BE39":
		return NewAESECBLinux(Key4BA5496A_Key1, Key4BA5496A_Key2), nil
	case "45433DCF-9ECA-4BE5-83F2-F92BA0B4F291":
		return NewAESCBCLinux(Key45433DCF_Key1, Key45433DCF_Key2), nil
	case "60639D8B-272E-4A4D-976E-AA270987A169":
		return NewModXTEALinux(Key60639D8B_Key1, Key60639D8B_Key2, Key60639D8B_Key3), nil
	case "AB6C8EBE-B8F8-4C08-8222-69A3B5E86A91":
		return NewAB6C8Linux(KeyAB6C8EBE_Key1, KeyAB6C8EBE_Key2, KeyAB6C8EBE_Key3, KeyAB6C8EBE_IV), nil
	case "B306E770-B7D5-49F2-A574-BCE2C5C650ED":
		b306Key := make([]byte, 48)
		copy(b306Key[0:8], KeyB306E770_Key1)
		copy(b306Key[8:16], KeyB306E770_Key2)
		copy(b306Key[16:24], KeyB306E770_Key3)
		copy(b306Key[24:32], KeyB306E770_Key4)
		copy(b306Key[32:40], KeyB306E770_Key5)
		copy(b306Key[40:48], KeyB306E770_Key6)
		return NewDESECBSix(b306Key), nil

	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algoID)
	}
}
