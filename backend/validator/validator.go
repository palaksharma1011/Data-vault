// Package validator inspects an uploaded file (already saved in a quarantine
// directory) and decides: ACCEPT or REJECT. Nothing is encrypted or stored
// until Validate() returns nil error.
package validator

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// ---------- result / error types ----------

type Result struct {
	Kind   string // real detected type: pdf, png, zip, text...
	SHA256 string // hash of the plaintext file (store it, put it in audit log)
	Size   int64
}

// RejectError carries a short code (for the audit log) and a reason.
type RejectError struct{ Code, Reason string }

func (e *RejectError) Error() string { return e.Code + ": " + e.Reason }

func reject(code, format string, a ...any) error {
	return &RejectError{Code: code, Reason: fmt.Sprintf(format, a...)}
}

// Scanner is the antivirus hook (ClamAV below).
type Scanner interface {
	Scan(ctx context.Context, path string) error
}

type Validator struct {
	MaxSize int64   // e.g. 25 << 20
	Scanner Scanner // may be nil only in dev
}

// Allowlist: extension -> real content type it must have.
var extKind = map[string]string{
	".pdf": "pdf", ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif",
	".txt": "text", ".csv": "text",
	".docx": "zip", ".xlsx": "zip", ".pptx": "zip",
}

// ---------- main pipeline ----------

func (v *Validator) Validate(ctx context.Context, path, origName string) (*Result, error) {
	// 1. Size
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() == 0 {
		return nil, reject("EMPTY", "file is empty")
	}
	if st.Size() > v.MaxSize {
		return nil, reject("TOO_LARGE", "file is %d bytes, limit is %d", st.Size(), v.MaxSize)
	}

	// 2. Extension allowlist
	ext := strings.ToLower(filepath.Ext(origName))
	want, ok := extKind[ext]
	if !ok {
		return nil, reject("EXT_NOT_ALLOWED", "extension %q is not allowed", ext)
	}

	// 3. Real type from magic bytes (never trust extension / Content-Type header)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]

	if sig := blockedSignature(head); sig != "" {
		return nil, reject("EXECUTABLE", "file looks like %s", sig)
	}
	got := sniff(head)
	if got != want {
		return nil, reject("TYPE_MISMATCH", "extension %s but content is %s", ext, got)
	}

	// 4. Hash (fingerprint of exactly what we validated)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	// 5. Structure / corruption + embedded-threat checks per type
	switch got {
	case "pdf":
		err = checkPDF(path)
	case "zip":
		err = checkOOXML(path)
	case "png", "jpeg", "gif":
		err = checkImage(path)
	case "text":
		err = checkText(path)
	}
	if err != nil {
		return nil, err
	}

	// 6. Antivirus scan
	if v.Scanner != nil {
		if err := v.Scanner.Scan(ctx, path); err != nil {
			return nil, err
		}
	}

	return &Result{Kind: got, SHA256: hex.EncodeToString(h.Sum(nil)), Size: st.Size()}, nil
}

// ---------- type detection ----------

func blockedSignature(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("MZ")):
		return "a Windows executable (PE)"
	case bytes.HasPrefix(b, []byte("\x7fELF")):
		return "a Linux executable (ELF)"
	case bytes.HasPrefix(b, []byte{0xCF, 0xFA, 0xED, 0xFE}),
		bytes.HasPrefix(b, []byte{0xCE, 0xFA, 0xED, 0xFE}),
		bytes.HasPrefix(b, []byte{0xCA, 0xFE, 0xBA, 0xBE}):
		return "a macOS/Java executable"
	case bytes.HasPrefix(b, []byte("#!")):
		return "a script (shebang)"
	}
	return ""
}

func sniff(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("%PDF-")):
		return "pdf"
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return "png"
	case bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}):
		return "jpeg"
	case bytes.HasPrefix(b, []byte("GIF87a")), bytes.HasPrefix(b, []byte("GIF89a")):
		return "gif"
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		return "zip"
	case bytes.IndexByte(b, 0) < 0:
		return "text" // fully verified in checkText
	}
	return "unknown"
}

// ---------- per-type checks ----------

func checkText(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return reject("CORRUPT_TEXT", "not valid UTF-8 text")
	}
	return nil
}

func checkImage(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	cfg, _, err := image.DecodeConfig(f)
	if err != nil {
		return reject("CORRUPT_IMAGE", "bad image header: %v", err)
	}
	if int64(cfg.Width)*int64(cfg.Height) > 100_000_000 { // decompression-bomb guard
		return reject("IMAGE_TOO_BIG", "%dx%d pixels", cfg.Width, cfg.Height)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, _, err := image.Decode(f); err != nil { // full decode proves data is intact
		return reject("CORRUPT_IMAGE", "cannot decode: %v", err)
	}
	return nil
}

// Active-content markers inside a PDF. Their presence = reject.
var pdfRisky = []string{"/JavaScript", "/JS", "/Launch", "/OpenAction", "/EmbeddedFile", "/RichMedia", "/AA"}

func checkPDF(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		return reject("CORRUPT_PDF", "missing PDF header")
	}
	tail := data
	if len(tail) > 1024 {
		tail = tail[len(tail)-1024:]
	}
	if !bytes.Contains(tail, []byte("%%EOF")) {
		return reject("CORRUPT_PDF", "missing %%EOF (truncated file?)")
	}
	for _, tok := range pdfRisky {
		if bytes.Contains(data, []byte(tok)) {
			return reject("PDF_ACTIVE_CONTENT", "contains %s", tok)
		}
	}
	return nil
}

var badEntryExt = map[string]bool{
	".exe": true, ".dll": true, ".bat": true, ".cmd": true, ".ps1": true,
	".vbs": true, ".js": true, ".scr": true, ".jar": true, ".sh": true,
}

const (
	maxZipEntries  = 2000
	maxZipTotal    = 300 << 20 // 300 MB uncompressed
	maxZipRatio    = 100       // uncompressed/compressed
	ratioMinSizeKB = 1024
)

// checkOOXML validates .docx/.xlsx/.pptx (they are ZIP files).
func checkOOXML(path string) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return reject("CORRUPT_ZIP", "cannot open archive: %v", err)
	}
	defer zr.Close()

	if len(zr.File) > maxZipEntries {
		return reject("ZIP_BOMB", "%d entries", len(zr.File))
	}

	hasContentTypes := false
	var total int64
	for _, e := range zr.File {
		name := e.Name
		if name == "[Content_Types].xml" {
			hasContentTypes = true
		}
		// path traversal (zip-slip)
		if strings.Contains(name, "..") || strings.HasPrefix(name, "/") || strings.Contains(name, `\`) {
			return reject("ZIP_TRAVERSAL", "bad entry name %q", name)
		}
		// macros and executables hidden inside Office files
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, "vbaproject.bin") {
			return reject("MACRO", "contains VBA macros")
		}
		if badEntryExt[strings.ToLower(filepath.Ext(lower))] {
			return reject("EMBEDDED_EXECUTABLE", "contains %q", name)
		}
		// declared-size sanity / ratio
		if e.CompressedSize64 > 0 && e.UncompressedSize64 > ratioMinSizeKB*1024 &&
			e.UncompressedSize64/e.CompressedSize64 > maxZipRatio {
			return reject("ZIP_BOMB", "entry %q ratio too high", name)
		}
		// Actually read the entry: verifies CRC (corruption) and real size
		rc, err := e.Open()
		if err != nil {
			return reject("CORRUPT_ZIP", "entry %q: %v", name, err)
		}
		limit := int64(e.UncompressedSize64) + 1
		nread, err := io.Copy(io.Discard, io.LimitReader(rc, limit))
		rc.Close()
		if err != nil {
			return reject("CORRUPT_ZIP", "entry %q: %v", name, err)
		}
		if nread > int64(e.UncompressedSize64) {
			return reject("ZIP_BOMB", "entry %q larger than declared", name)
		}
		total += nread
		if total > maxZipTotal {
			return reject("ZIP_BOMB", "total uncompressed size too large")
		}
	}
	if !hasContentTypes {
		return reject("NOT_OFFICE_FILE", "[Content_Types].xml missing")
	}
	return nil
}

// ---------- ClamAV (clamd) scanner ----------

// ClamAV talks to a running clamd daemon using the INSTREAM command.
// Addr example: "127.0.0.1:3310" (tcp) or "/var/run/clamav/clamd.ctl" (unix).
type ClamAV struct {
	Network string // "tcp" or "unix"
	Addr    string
	Timeout time.Duration
}

func (c *ClamAV) Scan(ctx context.Context, path string) error {
	d := net.Dialer{Timeout: c.Timeout}
	conn, err := d.DialContext(ctx, c.Network, c.Addr)
	if err != nil {
		// FAIL CLOSED: if scanner is down, do not accept the file
		return fmt.Errorf("antivirus unavailable: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, 64*1024)
	lenBuf := make([]byte, 4)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(lenBuf, uint32(n))
			if _, err := conn.Write(lenBuf); err != nil {
				return err
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil { // end of stream
		return err
	}

	resp, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	msg := strings.TrimRight(string(resp), "\x00\n ")
	switch {
	case strings.HasSuffix(msg, "OK"):
		return nil
	case strings.HasSuffix(msg, "FOUND"):
		return reject("MALWARE", "%s", msg)
	default:
		return fmt.Errorf("antivirus error: %s", msg)
	}
}