package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"
)

var numReaders int = 0
var numWriters int = 0

func getNonce(i int) *[24]byte {
	var buf []byte = make([]byte, 24)
	binary.PutVarint(buf, int64(i))
	if len(buf) > 24 {
		panic("nonce is too big!")
	}
	var arr [24]byte
	copy(arr[:], buf)
	return &arr
}

type SecureReader struct {
	r         io.Reader
	priv, pub *[32]byte
	nonce     *[24]byte
}

func (r SecureReader) Read(p []byte) (int, error) {
	message := make([]byte, 1024)
	n, err := r.r.Read(message)
	if err != nil {
		return n, err
	}
	message = message[:n]

	decrypted, ok := box.Open(nil, message, r.nonce, r.pub, r.priv)
	if !ok {
		panic("invalid")
	}
	copy(p, decrypted)

	return len(decrypted), nil
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	nonce := getNonce(numReaders)
	numReaders++
	return SecureReader{r, priv, pub, nonce}
}

type SecureWriter struct {
	w         io.Writer
	priv, pub *[32]byte
	nonce     *[24]byte
}

func (w SecureWriter) Write(p []byte) (int, error) {
	encrypted := box.Seal(nil, p, w.nonce, w.pub, w.priv)
	w.w.Write(encrypted)

	return len(encrypted), nil
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	nonce := getNonce(numWriters)
	numWriters++
	return SecureWriter{w, priv, pub, nonce}
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	return nil, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	return nil
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
