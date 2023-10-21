package zipcrypto

import (
	"archive/zip"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidHeader        = errors.New("invalid header")
	ErrEncryptionFlagNotSet = fmt.Errorf("%w: encryption flag not set", ErrInvalidHeader)
)

// NewWriter uses a properly configured zip.FileHeader and password to create a
// writer that encrypts as data is written to it.
//
// Note: due to this implementation being external to archive/zip, the
// zip.FileHeader must be filled out (including the Flags, CRC32, and the
// CompressedSize64 must be set 12 bytes longer than the actual value).
//
// This is because (zip.Writer).CreateRaw creates the writer that must be
// wrapped by this function and the zip.FileHeader cannot be modified once
// CreateRaw has been called.
func NewWriter(fh *zip.FileHeader, w io.Writer, password []byte) (io.Writer, error) {
	if fh.Flags&0x1 == 0 {
		return nil, ErrEncryptionFlagNotSet
	}

	zw := &writer{fh: fh, w: w}
	zw.keys.init(password)
	return zw, nil
}

type writer struct {
	fh   *zip.FileHeader
	w    io.Writer
	keys keys

	headerWritten bool
}

// Write encrypts bytes as they are written to the underlying writer.
func (w *writer) Write(buf []byte) (int, error) {
	if !w.headerWritten {
		w.headerWritten = true
		if err := w.writeHeader(); err != nil {
			return 0, err
		}
	}

	return w.w.Write(w.encrypt(buf))
}
func (w *writer) hasDataDescriptor() bool {
	return w.fh != nil && w.fh.Flags&0x8 != 0
}

func (w *writer) writeHeader() error {
	var header [12]byte
	_, err := io.ReadFull(rand.Reader, header[:11])
	if err != nil {
		return err
	}

	if w.hasDataDescriptor() {
		header[11] = byte(w.fh.ModifiedTime >> 8)
	} else {
		header[11] = byte(w.fh.CRC32 >> 24)
	}

	_, err = w.w.Write(w.encrypt(header[:]))
	return err
}

func (w *writer) encrypt(buf []byte) []byte {
	encrypted := make([]byte, len(buf))
	for i, c := range buf {
		encrypted[i] = c ^ w.keys.byte()
		w.keys.updateKeys(c)
	}
	return encrypted
}
