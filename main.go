package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"
)

// Embed the nonce!
// https://github.com/ereyes01/cryptohelper/blob/master/cryptohelper.go#L31
// also helpful:
// http://pynacl.readthedocs.org/en/latest/public/
// wrapper types: http://play.golang.org/p/ssz2AKIj_y

type SecureReader struct {
	r         io.Reader
	priv, pub *[32]byte
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

	decrypted, ok := box.Open([]byte{}, message[24:], &nonce, r.pub, r.priv)
	if !ok {
		log.Fatalln("unable to open box")
	}
	copy(p, decrypted)

	return len(decrypted), nil
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	return SecureReader{r, priv, pub}
}

type SecureWriter struct {
	w         io.Writer
	priv, pub *[32]byte
}

func (w SecureWriter) Write(p []byte) (int, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, err
	}

	encrypted := box.Seal(nonce[:], p, &nonce, w.pub, w.priv)
	w.w.Write(encrypted)

	return len(encrypted), nil
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return SecureWriter{w, priv, pub}
}

type SecureReadWriteCloser struct {
	sr   io.Reader
	sw   io.Writer
	conn net.Conn
}

func (srwc SecureReadWriteCloser) Read(p []byte) (int, error) {
	return srwc.sr.Read(p)
}

func (srwc SecureReadWriteCloser) Write(p []byte) (int, error) {
	return srwc.sw.Write(p)
}

func (srwc SecureReadWriteCloser) Close() error {
	return srwc.conn.Close()
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalln("error generating keys", err)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalln("error dialing server", err)
	}
	sr := NewSecureReader(conn, priv, pub)
	sw := NewSecureWriter(conn, priv, pub)

	srwc := SecureReadWriteCloser{sr, sw, conn}

	return srwc, nil
}

// Serve starts a secure echo server on the given listener.
// http://golang.org/src/net/http/server.go?s=51504:51550#L1714
// http://loige.co/simple-echo-server-written-in-go-dockerized/
func Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatalln("error accepting connection", err)
		}
		go handleRequest(conn)
	}
}

func handleRequest(conn net.Conn) {
	buf := make([]byte, 1024)
	// Read the incoming connection into the buffer.
	_, err := conn.Read(buf)
	if err != nil {
		log.Fatalln("error reading request", err)
	}

	n := bytes.Index(buf, []byte{0})

	conn.Write(buf[:n])
	conn.Close()
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
