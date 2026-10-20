package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/bcrypt"
)

// --- Key management module ---
//
// Kept deliberately small and isolated (own file, own type) so it can
// later be replaced by a dedicated KMS/HSM without touching the rest of
// the application. The master key plays the role a KMS would play: it
// never leaves this module, every file gets its own random Data
// Encryption Key (DEK), and DEKs / MFA secrets are envelope-encrypted by
// the master key with context-binding AAD.

type KeyManager struct {
	masterKey []byte // 32 bytes -> AES-256
}

// NewKeyManager loads the master key from VAULT_MASTER_KEY (base64,
// 32 bytes) if set, otherwise from (or into) a local keyfile so restarts
// don't orphan already-encrypted files.
func NewKeyManager(dataDir string) (*KeyManager, error) {
	if b64 := os.Getenv("VAULT_MASTER_KEY"); b64 != "" {
		key, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(key) != 32 {
			return nil, errors.New("VAULT_MASTER_KEY must be base64-encoded 32 bytes")
		}
		return &KeyManager{masterKey: key}, nil
	}
	keyPath := dataDir + "/master.key"
	if b, err := os.ReadFile(keyPath); err == nil {
		key, err := base64.StdEncoding.DecodeString(string(b))
		if err == nil && len(key) == 32 {
			return &KeyManager{masterKey: key}, nil
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		return nil, err
	}
	return &KeyManager{masterKey: key}, nil
}

// NewDEK generates a fresh random 32-byte Data Encryption Key for one file.
func (km *KeyManager) NewDEK() ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	return dek, nil
}

// Seal encrypts plaintext under the master key (AES-256-GCM) and binds
// it to aad, so a sealed blob cannot be swapped between contexts.
func (km *KeyManager) Seal(plaintext, aad []byte) (string, error) {
	gcm, err := newGCM(km.masterKey)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, aad)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal.
func (km *KeyManager) Open(sealedB64 string, aad []byte) ([]byte, error) {
	sealed, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(km.masterKey)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(sealed) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, sealed[:ns], sealed[ns:], aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// AAD helpers: bind ciphertext to the identity/classification of what it
// protects.
func fileAAD(fileID string, class Classification) []byte {
	return []byte("vault-file-v2|" + fileID + "|" + string(class))
}
func dekAAD(fileID string) []byte { return []byte("vault-dek-v2|" + fileID) }
func mfaAAD(userID string) []byte { return []byte("vault-mfa-v1|" + userID) }

// --- Streaming file encryption (chunked AES-256-GCM) ---
//
// Files are processed in 64 KiB chunks so memory use is constant no
// matter how large the file is. Each chunk is an independent GCM message
//   nonce = prefix(7 random bytes) || counter(4 bytes BE) || last-flag(1 byte)
// with the file AAD (file id + classification). The counter prevents
// reordering, the last-flag prevents truncation, the AAD prevents moving
// ciphertext to another file record or changing its classification label.
//
// On-disk format:  "VLT2" | prefix(7) | chunk_0 | chunk_1 | ...

const (
	chunkSize    = 64 * 1024
	tagSize      = 16
	noncePrefLen = 7
	fileMagic    = "VLT2"
)

var (
	ErrAuthFailed = errors.New("decryption failed: data is corrupted or has been tampered with")
	ErrTruncated  = errors.New("decryption failed: encrypted file is truncated")
)

func chunkNonce(prefix []byte, counter uint32, last bool) []byte {
	n := make([]byte, 12)
	copy(n, prefix)
	binary.BigEndian.PutUint32(n[7:11], counter)
	if last {
		n[11] = 1
	}
	return n
}

// EncryptStream encrypts src into dst under a fresh DEK. It returns the
// plaintext size and the wrapped DEK to store with the file record.
func EncryptStream(km *KeyManager, dst io.Writer, src io.Reader, fileID string, class Classification) (int64, string, error) {
	dek, err := km.NewDEK()
	if err != nil {
		return 0, "", err
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return 0, "", err
	}
	wrapped, err := km.Seal(dek, dekAAD(fileID))
	if err != nil {
		return 0, "", err
	}
	prefix := make([]byte, noncePrefLen)
	if _, err := rand.Read(prefix); err != nil {
		return 0, "", err
	}
	if _, err := dst.Write(append([]byte(fileMagic), prefix...)); err != nil {
		return 0, "", err
	}
	aad := fileAAD(fileID, class)

	cur := make([]byte, chunkSize)
	nxt := make([]byte, chunkSize)
	var total int64
	var counter uint32

	curN, err := io.ReadFull(src, cur)
	last := false
	switch err {
	case nil:
	case io.EOF, io.ErrUnexpectedEOF:
		last = true
	default:
		return 0, "", err
	}
	for {
		nxtN := 0
		if !last {
			nxtN, err = io.ReadFull(src, nxt)
			switch err {
			case nil:
			case io.EOF:
				nxtN, last = 0, true
			case io.ErrUnexpectedEOF:
				// short read -> the *next* chunk will be the last one
			default:
				return 0, "", err
			}
		}
		ct := gcm.Seal(nil, chunkNonce(prefix, counter, last), cur[:curN], aad)
		if _, err := dst.Write(ct); err != nil {
			return 0, "", err
		}
		total += int64(curN)
		if last {
			break
		}
		counter++
		if counter == ^uint32(0) {
			return 0, "", errors.New("file too large")
		}
		cur, nxt = nxt, cur
		curN = nxtN
		if curN < chunkSize {
			// We just consumed the short tail into nxt -> it is the final chunk.
			// (Handled on the next loop iteration by marking last.)
			last = true
		}
	}
	return total, wrapped, nil
}

type decryptReader struct {
	r       *bufio.Reader
	gcm     cipher.AEAD
	prefix  []byte
	aad     []byte
	counter uint32
	pending []byte
	done    bool
}

func (d *decryptReader) Read(p []byte) (int, error) {
	for len(d.pending) == 0 {
		if d.done {
			return 0, io.EOF
		}
		if err := d.nextChunk(); err != nil {
			return 0, err
		}
	}
	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}

func (d *decryptReader) nextChunk() error {
	ct := make([]byte, chunkSize+tagSize)
	n, err := io.ReadFull(d.r, ct)
	last := false
	switch err {
	case nil:
		if _, perr := d.r.Peek(1); perr == io.EOF {
			last = true
		}
	case io.EOF:
		return ErrTruncated // ran out of data before the final chunk
	case io.ErrUnexpectedEOF:
		last = true
	default:
		return err
	}
	if n < tagSize {
		return ErrTruncated
	}
	pt, err := d.gcm.Open(nil, chunkNonce(d.prefix, d.counter, last), ct[:n], d.aad)
	if err != nil {
		return ErrAuthFailed
	}
	d.counter++
	d.pending = pt
	d.done = last
	return nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

// OpenFile returns a reader yielding the verified plaintext of a stored
// file. Plaintext of each chunk is released only after that chunk's
// authentication tag verified. Only ever called after the policy engine
// returned ALLOW.
func OpenFile(km *KeyManager, f *FileResource) (io.ReadCloser, error) {
	if f.EncVersion < 2 {
		return openLegacy(km, f)
	}
	dek, err := km.Open(f.WrappedKey, dekAAD(f.ID))
	if err != nil {
		return nil, ErrAuthFailed
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	fh, err := os.Open(f.EncPath)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(fh, chunkSize+tagSize+1)
	hdr := make([]byte, len(fileMagic)+noncePrefLen)
	if _, err := io.ReadFull(br, hdr); err != nil || string(hdr[:4]) != fileMagic {
		fh.Close()
		return nil, ErrTruncated
	}
	dr := &decryptReader{r: br, gcm: gcm, prefix: hdr[4:], aad: fileAAD(f.ID, f.Classification)}
	return readCloser{dr, fh}, nil
}

// openLegacy reads files written by the original single-shot format
// (no AAD). Kept so data created before this upgrade stays readable.
func openLegacy(km *KeyManager, f *FileResource) (io.ReadCloser, error) {
	dek, err := km.Open(f.WrappedKey, nil)
	if err != nil {
		return nil, ErrAuthFailed
	}
	ct, err := os.ReadFile(f.EncPath)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(f.Nonce)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return io.NopCloser(bytes.NewReader(pt)), nil
}

// --- Password hashing (bcrypt) ---

var bcryptCost = 12

const maxPasswordBytes = 72 // bcrypt input limit

func HashPassword(password string) (string, error) {
	if len(password) > maxPasswordBytes {
		return "", errors.New("password too long")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	return string(b), err
}

// VerifyPassword checks a password. Hashes created by the old salted
// SHA-256 scheme (salt != "") are still accepted once; needsRehash tells
// the caller to upgrade the stored hash to bcrypt.
func VerifyPassword(password, hash, salt string) (ok bool, needsRehash bool) {
	if salt != "" {
		sum := sha256.Sum256([]byte(salt + ":" + password))
		legacy := base64.StdEncoding.EncodeToString(sum[:])
		ok = subtle.ConstantTimeCompare([]byte(legacy), []byte(hash)) == 1
		return ok, ok
	}
	if len(password) > maxPasswordBytes {
		return false, false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil, false
}

// dummyHash is compared against when a username does not exist, so
// "unknown user" and "wrong password" take the same time.
var dummyHash, _ = HashPassword("dummy-password-for-timing-equalisation")

func burnPasswordTime(password string) {
	_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
}

func ValidatePasswordStrength(username, password string) error {
	if len(password) < 10 {
		return fmt.Errorf("password must be at least 10 characters")
	}
	if len(password) > maxPasswordBytes {
		return fmt.Errorf("password must be at most %d bytes", maxPasswordBytes)
	}
	if password == username {
		return fmt.Errorf("password must not equal the username")
	}
	var letter, digit bool
	for _, c := range password {
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			letter = true
		}
	}
	if !letter || !digit {
		return fmt.Errorf("password must contain at least one letter and one digit")
	}
	return nil
}
