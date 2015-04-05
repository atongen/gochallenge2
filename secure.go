package main

import (
	"crypto/rand"
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/nacl/box"
)

// A SecureReader wraps an io.Reader and a shared key
type SecureReader struct {
	r         io.Reader
	sharedKey *[32]byte
}

func (r SecureReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	message := make([]byte, 1024)
	n, err := r.r.Read(message)
	if err != nil {
		return n, err
	}
	message = message[:n]

	var nonce [24]byte
	copy(nonce[:], message[:24])

	decrypted, ok := box.OpenAfterPrecomputation([]byte{}, message[24:], &nonce, r.sharedKey)
	if !ok {
		return 0, errors.New("unable to open the box")
	}
	copy(p, decrypted)

	return len(decrypted), nil
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	var sharedKey [32]byte
	box.Precompute(&sharedKey, pub, priv)
	return &SecureReader{r, &sharedKey}
}

type SecureWriter struct {
	w         io.Writer
	sharedKey *[32]byte
}

func (w SecureWriter) Write(p []byte) (int, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, err
	}

	encrypted := box.SealAfterPrecomputation(nonce[:], p, &nonce, w.sharedKey)
	w.w.Write(encrypted)

	return len(encrypted), nil
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	var sharedKey [32]byte
	box.Precompute(&sharedKey, pub, priv)
	return &SecureWriter{w, &sharedKey}
}

type SecureReadWriteCloser struct {
	sr io.Reader
	sw io.Writer
	net.Conn
}

func NewSecureReadWriteCloser(conn net.Conn, priv, pub *[32]byte) io.ReadWriteCloser {
	sr := NewSecureReader(conn, priv, pub)
	sw := NewSecureWriter(conn, priv, pub)

	return &SecureReadWriteCloser{sr, sw, conn}
}

func (srwc SecureReadWriteCloser) Read(p []byte) (int, error) {
	return srwc.sr.Read(p)
}

func (srwc SecureReadWriteCloser) Write(p []byte) (int, error) {
	return srwc.sw.Write(p)
}

func GenerateKey() (publicKey, privateKey *[32]byte, err error) {
	return box.GenerateKey(rand.Reader)
}
