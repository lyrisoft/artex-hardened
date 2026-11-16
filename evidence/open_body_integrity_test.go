package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestOpenVerifiedEvidenceDoesNotReopenReplacedPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not permit renaming this open file")
	}
	dir := t.TempDir()
	original := []byte("synthetic original evidence")
	digest := sha256.Sum256(original)
	hash := hex.EncodeToString(digest[:])
	path, err := hashPath(dir, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openVerifiedFile(path, hash, int64(len(original)), func(open *os.File, want string, length int64) error {
		if err := verifyOpenFile(open, want, length); err != nil {
			return err
		}
		if err := os.Rename(path, path+".replaced"); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("synthetic replacement"), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("returned unverified replacement: %q err=%v", got, err)
	}
	store := New(nil, nil, dir)
	snapshot := db.TrafficEvidenceSnapshot{RespHash: hash, RespLen: int64(len(original))}
	if reopened, _, err := store.OpenBody(snapshot, "response"); err == nil {
		reopened.Close()
		t.Fatal("subsequent open accepted tampered evidence")
	}
}

func TestOpenVerifiedEvidenceRejectsWrongLengthAndContent(t *testing.T) {
	dir := t.TempDir()
	original := []byte("synthetic evidence")
	digest := sha256.Sum256(original)
	hash := hex.EncodeToString(digest[:])
	path, err := hashPath(dir, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(nil, nil, dir)
	for _, snapshot := range []db.TrafficEvidenceSnapshot{
		{RespHash: hash, RespLen: int64(len(original) - 1)},
		{RespHash: hash, RespLen: -1},
	} {
		if f, _, err := store.OpenBody(snapshot, "response"); err == nil {
			f.Close()
			t.Fatal("invalid length accepted")
		}
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, len(original)), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, _, err := store.OpenBody(db.TrafficEvidenceSnapshot{RespHash: hash, RespLen: int64(len(original))}, "response"); err == nil {
		f.Close()
		t.Fatal("same-length tampering accepted")
	}
}
