package zipcrypto

import (
	"archive/zip"
	"errors"
	"io"
)

var (
	ErrInvalidPassword = errors.New("invalid password")
	ErrNotEncrypted    = errors.New("not encrypted with zipcrypto")
)

// NewReader creates a reader that validates the given password and decrypts
// data as it is read.
//
// The password is validated against the zip.FileHeader provided
func NewReader(fh *zip.FileHeader, r io.Reader, password []byte) (io.Reader, error) {
	if fh.Flags&0x1 == 0 {
		return nil, ErrNotEncrypted
	}

	zr := &reader{fh: fh, r: r}
	zr.keys.init(password)
	return zr, nil
}

type reader struct {
	fh   *zip.FileHeader
	r    io.Reader
	keys keys

	headerRead bool
}

// Read decrypts bytes while reading from the underlying reader.
func (r *reader) Read(buf []byte) (int, error) {
	if !r.headerRead {
		r.headerRead = true
		if err := r.readHeader(); err != nil {
			return 0, err
		}
	}

	n, err := r.r.Read(buf)
	r.decrypt(buf[:n])
	return n, err
}

func (r *reader) hasDataDescriptor() bool {
	return r.fh != nil && r.fh.Flags&0x8 != 0
}

func (r *reader) readHeader() error {
	var header [12]byte
	_, err := io.ReadFull(r.r, header[:])
	if err != nil {
		return err
	}

	r.decrypt(header[:])

	if r.fh != nil {
		var checkByte byte
		if r.hasDataDescriptor() {
			checkByte = byte(r.fh.ModifiedTime >> 8)
		} else {
			checkByte = byte(r.fh.CRC32 >> 24)
		}

		if checkByte != header[11] {
			return ErrInvalidPassword
		}
	}

	return nil
}

func (r *reader) decrypt(buf []byte) {
	for i, c := range buf {
		buf[i] = c ^ r.keys.byte()
		r.keys.updateKeys(buf[i])
	}
}
