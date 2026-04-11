package metadata

import (
	"os"
	"testing"
)

func TestFindXORKeyKasiski(t *testing.T) {
	testFile := os.Getenv("DISUNITY_TEST_ENCRYPTED_META")
	if testFile == "" {
		t.Skip("DISUNITY_TEST_ENCRYPTED_META not set")
	}

	data, err := os.ReadFile(testFile)
	if err != nil {
		t.Skipf("test file not found: %v", err)
	}

	t.Logf("file size: %d bytes", len(data))
	t.Logf("first 16 bytes: %x", data[:16])

	key, decrypted, err := FindXORKeyKasiski(data)
	if err != nil {
		t.Fatalf("Kasiski failed: %v", err)
	}

	t.Logf("found key: %q (hex: %x)", key.KeyString, key.Key[:])
	t.Logf("decrypted first 32 bytes: %x", decrypted[:32])

	if decrypted[0] != 0xaf || decrypted[1] != 0x1b || decrypted[2] != 0xb1 || decrypted[3] != 0xfa {
		t.Errorf("invalid magic after decryption: %x", decrypted[:4])
	}
}
