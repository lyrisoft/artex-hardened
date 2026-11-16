package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
)

// Small bounded chunks let a download recheck the bytes it actually returns,
// without copying an arbitrarily large body into memory or a mutable temp file.
const verifiedBodyChunkSize = 256 * 1024

var errEvidenceChanged = errors.New("evidence body changed during read")

var _ io.ReadSeekCloser = (*VerifiedBody)(nil)
var _ io.ReaderAt = (*VerifiedBody)(nil)

// VerifiedBody reads and seeks over the exact body authenticated at open time.
// Each chunk is copied into private memory and rechecked before it is returned,
// so a process writing the same inode cannot substitute bytes after verification.
// The original file and metadata are still in the shared legacy store; this
// cannot prevent deletion, denial of service, or a forged metadata/hash pair.
// Independent evidence custody and scoped authorization remain necessary.
//
// OpenBody previously returned *os.File; callers should use Read, ReadAt, Seek
// and Close rather than relying on operating-system file descriptor methods.
type VerifiedBody struct {
	mu           sync.Mutex
	file         *os.File
	size, offset int64
	hashes       [][sha256.Size]byte
	chunk        []byte
	chunkIndex   int64
	chunkLen     int
	closed       bool
}

func openVerifiedBody(path, hash string, length int64) (*VerifiedBody, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	body, err := newVerifiedBody(f, hash, length)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return body, nil
}

func newVerifiedBody(f *os.File, hash string, length int64) (*VerifiedBody, error) {
	if f == nil || length < 0 || length == math.MaxInt64 {
		return nil, errors.New("invalid evidence body")
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != length {
		return nil, fmt.Errorf("evidence body verification failed: %s", hash)
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	result := &VerifiedBody{file: f, size: length, chunkIndex: -1}
	if length > 0 {
		result.chunk = make([]byte, verifiedBodyChunkSize)
	}
	full := sha256.New()
	remaining := length
	for remaining > 0 {
		count := int64(verifiedBodyChunkSize)
		if remaining < count {
			count = remaining
		}
		data := result.chunk[:int(count)]
		if _, err := io.ReadFull(f, data); err != nil {
			return nil, fmt.Errorf("evidence body verification failed: %w", err)
		}
		_, _ = full.Write(data)
		result.hashes = append(result.hashes, sha256.Sum256(data))
		remaining -= count
	}
	var extra [1]byte
	n, readErr := f.Read(extra[:])
	if n != 0 || readErr != io.EOF || hex.EncodeToString(full.Sum(nil)) != hash {
		if readErr != nil && readErr != io.EOF {
			return nil, readErr
		}
		return nil, fmt.Errorf("evidence body verification failed: %s", hash)
	}
	return result, nil
}

// verifiedChunk copies a single chunk into private memory before verifying it.
// Callers hold b.mu and never receive the backing slice itself.
func (b *VerifiedBody) verifiedChunk(index int64) error {
	if index < 0 || index >= int64(len(b.hashes)) {
		return errEvidenceChanged
	}
	if b.chunkIndex == index {
		return nil
	}
	b.chunkIndex = -1
	start := index * verifiedBodyChunkSize
	size := int64(verifiedBodyChunkSize)
	if b.size-start < size {
		size = b.size - start
	}
	n, err := b.file.ReadAt(b.chunk[:int(size)], start)
	if int64(n) != size || (err != nil && err != io.EOF) || sha256.Sum256(b.chunk[:int(size)]) != b.hashes[int(index)] {
		return errEvidenceChanged
	}
	b.chunkIndex = index
	b.chunkLen = int(size)
	return nil
}

func (b *VerifiedBody) Read(p []byte) (int, error) {
	if b == nil {
		return 0, os.ErrInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.file == nil {
		return 0, os.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	if b.offset >= b.size {
		return 0, io.EOF
	}
	index := b.offset / verifiedBodyChunkSize
	if err := b.verifiedChunk(index); err != nil {
		return 0, err
	}
	within := int(b.offset % verifiedBodyChunkSize)
	n := copy(p, b.chunk[within:b.chunkLen])
	b.offset += int64(n)
	return n, nil
}

// ReadAt verifies each affected chunk before copying it to p. As with a normal
// ReaderAt, a short result returns an error and does not change the seek offset.
func (b *VerifiedBody) ReadAt(p []byte, offset int64) (int, error) {
	if b == nil {
		return 0, os.ErrInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.file == nil {
		return 0, os.ErrClosed
	}
	if offset < 0 {
		return 0, errors.New("negative evidence read offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for len(p) > 0 && offset < b.size {
		index := offset / verifiedBodyChunkSize
		if err := b.verifiedChunk(index); err != nil {
			return total, err
		}
		within := int(offset % verifiedBodyChunkSize)
		n := copy(p, b.chunk[within:b.chunkLen])
		p = p[n:]
		total += n
		offset += int64(n)
	}
	if len(p) > 0 {
		return total, io.EOF
	}
	return total, nil
}

func (b *VerifiedBody) Seek(offset int64, whence int) (int64, error) {
	if b == nil {
		return 0, os.ErrInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.file == nil {
		return 0, os.ErrClosed
	}
	var base int64
	switch whence {
	case io.SeekStart:
		base = 0
	case io.SeekCurrent:
		base = b.offset
	case io.SeekEnd:
		base = b.size
	default:
		return 0, errors.New("invalid evidence seek origin")
	}
	if (offset < 0 && offset < -base) || (offset > 0 && offset > math.MaxInt64-base) {
		return 0, errors.New("invalid evidence seek offset")
	}
	b.offset = base + offset
	return b.offset, nil
}

func (b *VerifiedBody) Close() error {
	if b == nil {
		return os.ErrInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.file == nil {
		return os.ErrClosed
	}
	b.closed = true
	clear(b.chunk)
	b.hashes = nil
	return b.file.Close()
}
