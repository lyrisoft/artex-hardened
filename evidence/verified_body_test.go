package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func verifiedFixture(t *testing.T, content []byte) (*Store, db.TrafficEvidenceSnapshot, string) {
	t.Helper()
	dir := t.TempDir()
	digest := sha256.Sum256(content)
	hash := hex.EncodeToString(digest[:])
	path, err := hashPath(dir, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return New(nil, nil, dir), db.TrafficEvidenceSnapshot{RespHash: hash, RespLen: int64(len(content))}, path
}

func changeEvidenceAt(t *testing.T, path string, offset int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte{0xff, 0xfe, 0xfd}, offset); err != nil {
		t.Fatal(err)
	}
}

func TestVerifiedBodyRejectsInPlaceMutationBeforeRead(t *testing.T) {
	original := bytes.Repeat([]byte("synthetic evidence\n"), 20000)
	store, snapshot, path := verifiedFixture(t, original)
	body, _, err := store.OpenBody(snapshot, "response")
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	changeEvidenceAt(t, path, 0)
	dst := bytes.Repeat([]byte{0x42}, 16)
	n, err := body.Read(dst)
	if n != 0 || !errors.Is(err, errEvidenceChanged) || !bytes.Equal(dst, bytes.Repeat([]byte{0x42}, 16)) {
		t.Fatalf("tampered bytes delivered: n=%d err=%v", n, err)
	}
}

func TestVerifiedBodyReturnsOnlyCheckedChunksDuringMutation(t *testing.T) {
	original := bytes.Repeat([]byte("abcdefgh"), verifiedBodyChunkSize/4+9)
	store, snapshot, path := verifiedFixture(t, original)
	body, _, err := store.OpenBody(snapshot, "response")
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	prefix := make([]byte, 7)
	if _, err := io.ReadFull(body, prefix); err != nil || !bytes.Equal(prefix, original[:7]) {
		t.Fatalf("prefix=%q err=%v", prefix, err)
	}
	// The first chunk is already private and verified. A later in-place write
	// cannot change it; a changed next chunk must fail before any of its bytes
	// are copied to the caller.
	changeEvidenceAt(t, path, 8)
	changeEvidenceAt(t, path, int64(verifiedBodyChunkSize))
	rest := make([]byte, verifiedBodyChunkSize-7)
	if _, err := io.ReadFull(body, rest); err != nil || !bytes.Equal(rest, original[7:verifiedBodyChunkSize]) {
		t.Fatalf("cached verified chunk changed: %v", err)
	}
	partial := bytes.Repeat([]byte{0x42}, 12)
	n, err := body.ReadAt(partial, int64(verifiedBodyChunkSize-4))
	if n != 4 || !errors.Is(err, errEvidenceChanged) || !bytes.Equal(partial[:4], original[verifiedBodyChunkSize-4:verifiedBodyChunkSize]) || !bytes.Equal(partial[4:], bytes.Repeat([]byte{0x42}, 8)) {
		t.Fatalf("cross-chunk ReadAt delivered unverified bytes: n=%d err=%v", n, err)
	}
	dst := bytes.Repeat([]byte{0x42}, 32)
	n, err = body.Read(dst)
	if n != 0 || !errors.Is(err, errEvidenceChanged) || !bytes.Equal(dst, bytes.Repeat([]byte{0x42}, 32)) {
		t.Fatalf("tampered next chunk delivered: n=%d err=%v", n, err)
	}
	n, err = body.ReadAt(dst, int64(verifiedBodyChunkSize))
	if n != 0 || !errors.Is(err, errEvidenceChanged) {
		t.Fatalf("ReadAt accepted tampering: n=%d err=%v", n, err)
	}
}

func TestVerifiedBodySeekReadAtAndEmptyBody(t *testing.T) {
	original := bytes.Repeat([]byte("0123456789abcdef"), verifiedBodyChunkSize/8+2)
	store, snapshot, _ := verifiedFixture(t, original)
	body, total, err := store.OpenBody(snapshot, "response")
	if err != nil || total != int64(len(original)) {
		t.Fatalf("total=%d err=%v", total, err)
	}
	defer body.Close()
	start := int64(verifiedBodyChunkSize - 5)
	if offset, err := body.Seek(start, io.SeekStart); err != nil || offset != start {
		t.Fatalf("seek=%d err=%v", offset, err)
	}
	got := make([]byte, 20)
	if _, err := io.ReadFull(body, got); err != nil || !bytes.Equal(got, original[start:start+20]) {
		t.Fatalf("cross-chunk read mismatch: %v", err)
	}
	position := start + 20
	buf := make([]byte, 30)
	if n, err := body.ReadAt(buf, start-10); err != nil || n != len(buf) || !bytes.Equal(buf, original[start-10:start+20]) {
		t.Fatalf("ReadAt n=%d err=%v", n, err)
	}
	if offset, err := body.Seek(0, io.SeekCurrent); err != nil || offset != position {
		t.Fatalf("ReadAt changed offset=%d err=%v", offset, err)
	}
	if offset, err := body.Seek(-3, io.SeekEnd); err != nil || offset != int64(len(original)-3) {
		t.Fatalf("end seek=%d err=%v", offset, err)
	}
	tail, err := io.ReadAll(body)
	if err != nil || !bytes.Equal(tail, original[len(original)-3:]) {
		t.Fatalf("tail=%q err=%v", tail, err)
	}
	if n, err := body.ReadAt(make([]byte, 5), int64(len(original)-3)); n != 3 || err != io.EOF {
		t.Fatalf("short ReadAt n=%d err=%v", n, err)
	}
	for _, tc := range []struct {
		off    int64
		whence int
	}{{-1, io.SeekStart}, {math.MaxInt64, io.SeekEnd}, {0, 99}} {
		if _, err := body.Seek(tc.off, tc.whence); err == nil {
			t.Fatalf("invalid seek accepted: %+v", tc)
		}
	}
	if _, err := body.ReadAt(make([]byte, 1), -1); err == nil {
		t.Fatal("negative ReadAt accepted")
	}
	emptyStore, emptySnapshot, _ := verifiedFixture(t, nil)
	empty, _, err := emptyStore.OpenBody(emptySnapshot, "response")
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	if n, err := empty.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("empty body n=%d err=%v", n, err)
	}
}

func TestVerifiedBodyConcurrentReadAt(t *testing.T) {
	original := bytes.Repeat([]byte("synthetic-data-"), 50000)
	store, snapshot, _ := verifiedFixture(t, original)
	body, _, err := store.OpenBody(snapshot, "response")
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	var wg sync.WaitGroup
	errorsOut := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			offset := int64(i * 50000)
			out := make([]byte, 1000)
			n, err := body.ReadAt(out, offset)
			if err != nil || n != len(out) || !bytes.Equal(out, original[offset:offset+int64(len(out))]) {
				errorsOut <- errors.New("concurrent verified read mismatch")
			}
		}(i)
	}
	wg.Wait()
	close(errorsOut)
	for err := range errorsOut {
		t.Error(err)
	}
}

func TestVerifiedBodyUninitializedAndClosedFailSafely(t *testing.T) {
	var nilBody *VerifiedBody
	if _, err := nilBody.Read(make([]byte, 1)); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil read: %v", err)
	}
	if err := nilBody.Close(); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil close: %v", err)
	}
	var zero VerifiedBody
	if _, err := zero.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("zero read: %v", err)
	}
	if err := zero.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("zero close: %v", err)
	}
	store, snapshot, _ := verifiedFixture(t, []byte("synthetic"))
	body, _, err := store.OpenBody(snapshot, "response")
	if err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := body.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed read: %v", err)
	}
	if _, err := body.ReadAt(make([]byte, 1), 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed ReadAt: %v", err)
	}
	if _, err := body.Seek(0, io.SeekStart); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed seek: %v", err)
	}
}
