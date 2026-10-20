package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func init() { bcryptCost = 4 } // fast hashing in tests

func testKM(t *testing.T) *KeyManager {
	t.Helper()
	km, err := NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return km
}

func encryptToFile(t *testing.T, km *KeyManager, data []byte, id string, class Classification) *FileResource {
	t.Helper()
	path := filepath.Join(t.TempDir(), id+".enc")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	size, wrapped, err := EncryptStream(km, f, bytes.NewReader(data), id, class)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if size != int64(len(data)) {
		t.Fatalf("size %d != %d", size, len(data))
	}
	return &FileResource{ID: id, Classification: class, EncPath: path, WrappedKey: wrapped, EncVersion: 2, Size: size}
}

func decryptAll(km *KeyManager, f *FileResource) ([]byte, error) {
	rd, err := OpenFile(km, f)
	if err != nil {
		return nil, err
	}
	defer rd.Close()
	return io.ReadAll(rd)
}

func TestStreamRoundTripSizes(t *testing.T) {
	km := testKM(t)
	// empty, tiny, exactly one chunk, one chunk +1, exact multiple, multi-chunk with tail
	for _, n := range []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 2 * chunkSize, 3*chunkSize + 123} {
		data := make([]byte, n)
		_, _ = rand.Read(data)
		f := encryptToFile(t, km, data, "file_x", ClassConfidential)
		got, err := decryptAll(km, f)
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("size %d: plaintext mismatch", n)
		}
	}
}

func TestCiphertextHidesPlaintext(t *testing.T) {
	km := testKM(t)
	marker := bytes.Repeat([]byte("TOP-SECRET-MARKER"), 100)
	f := encryptToFile(t, km, marker, "file_m", ClassPublic)
	raw, _ := os.ReadFile(f.EncPath)
	if bytes.Contains(raw, []byte("TOP-SECRET")) {
		t.Fatal("plaintext visible in stored ciphertext")
	}
}

func TestTamperDetected(t *testing.T) {
	km := testKM(t)
	data := make([]byte, 2*chunkSize+10)
	_, _ = rand.Read(data)
	f := encryptToFile(t, km, data, "file_t", ClassConfidential)
	raw, _ := os.ReadFile(f.EncPath)
	raw[len(raw)/2] ^= 0x01
	_ = os.WriteFile(f.EncPath, raw, 0o600)
	if _, err := decryptAll(km, f); err == nil {
		t.Fatal("bit flip was not detected")
	}
}

func TestTruncationDetected(t *testing.T) {
	km := testKM(t)
	data := make([]byte, 3*chunkSize)
	_, _ = rand.Read(data)
	f := encryptToFile(t, km, data, "file_tr", ClassConfidential)
	raw, _ := os.ReadFile(f.EncPath)
	// cut exactly at a chunk boundary (drops the final chunk) and mid-chunk
	for _, cut := range []int{len(fileMagic) + noncePrefLen + 2*(chunkSize+tagSize), len(raw) - 5} {
		_ = os.WriteFile(f.EncPath, raw[:cut], 0o600)
		if _, err := decryptAll(km, f); err == nil {
			t.Fatalf("truncation at %d not detected", cut)
		}
	}
}

func TestChunkReorderDetected(t *testing.T) {
	km := testKM(t)
	data := make([]byte, 3*chunkSize)
	_, _ = rand.Read(data)
	f := encryptToFile(t, km, data, "file_ro", ClassConfidential)
	raw, _ := os.ReadFile(f.EncPath)
	h := len(fileMagic) + noncePrefLen
	c := chunkSize + tagSize
	swapped := append([]byte{}, raw[:h]...)
	swapped = append(swapped, raw[h+c:h+2*c]...)
	swapped = append(swapped, raw[h:h+c]...)
	swapped = append(swapped, raw[h+2*c:]...)
	_ = os.WriteFile(f.EncPath, swapped, 0o600)
	if _, err := decryptAll(km, f); err == nil {
		t.Fatal("chunk reorder not detected")
	}
}

// AAD binding: changing the classification label or the file id must
// make decryption fail.
func TestAADBindsIDAndClassification(t *testing.T) {
	km := testKM(t)
	f := encryptToFile(t, km, []byte("payroll"), "file_a", ClassHighlyConfidential)
	if got, err := decryptAll(km, f); err != nil || string(got) != "payroll" {
		t.Fatalf("baseline failed: %v", err)
	}
	relabel := *f
	relabel.Classification = ClassPublic // attacker edits the DB label
	if _, err := decryptAll(km, &relabel); err == nil {
		t.Fatal("decryption succeeded after classification was changed")
	}
	moved := *f
	moved.ID = "file_other" // ciphertext/wrapped key attached to another record
	if _, err := decryptAll(km, &moved); err == nil {
		t.Fatal("decryption succeeded under a different file id")
	}
}

func TestSealOpenAAD(t *testing.T) {
	km := testKM(t)
	s, _ := km.Seal([]byte("secret"), []byte("ctx-a"))
	if _, err := km.Open(s, []byte("ctx-b")); err == nil {
		t.Fatal("Open succeeded with wrong AAD")
	}
	if b, err := km.Open(s, []byte("ctx-a")); err != nil || string(b) != "secret" {
		t.Fatal("Open failed with right AAD")
	}
}

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("correct horse 42")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyPassword("correct horse 42", h, ""); !ok {
		t.Fatal("valid password rejected")
	}
	if ok, _ := VerifyPassword("wrong", h, ""); ok {
		t.Fatal("wrong password accepted")
	}
	if h[:2] != "$2" {
		t.Fatalf("expected bcrypt hash, got %q", h[:4])
	}
}

func TestLegacySHA256UpgradePath(t *testing.T) {
	// hash produced by the OLD implementation: base64(sha256(salt + ":" + password))
	salt := "c2FsdHNhbHRzYWx0"
	sum := sha256.Sum256([]byte(salt + ":" + "OldPass123"))
	legacy := base64.StdEncoding.EncodeToString(sum[:])
	ok, rehash := VerifyPassword("OldPass123", legacy, salt)
	if !ok || !rehash {
		t.Fatalf("legacy hash should verify and request a rehash (ok=%v rehash=%v)", ok, rehash)
	}
	if ok, _ := VerifyPassword("nope", legacy, salt); ok {
		t.Fatal("wrong password accepted against legacy hash")
	}
}

func TestPasswordStrength(t *testing.T) {
	bad := []string{"short1", "alllettersnodigit", "1234567890123", ""}
	for _, p := range bad {
		if ValidatePasswordStrength("bob", p) == nil {
			t.Errorf("weak password %q accepted", p)
		}
	}
	if err := ValidatePasswordStrength("bob", "GoodPass12345"); err != nil {
		t.Errorf("good password rejected: %v", err)
	}
}
