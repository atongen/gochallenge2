package main

import (
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
		log.Fatalln("unable to open box")
	}
	//println("read:", string(decrypted))
	copy(p, decrypted)

	return len(decrypted), nil
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	var sharedKey [32]byte
	box.Precompute(&sharedKey, pub, priv)
	return SecureReader{r, &sharedKey}
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
	//println("write:", string(p))

	encrypted := box.SealAfterPrecomputation(nonce[:], p, &nonce, w.sharedKey)
	w.w.Write(encrypted)

	return len(encrypted), nil
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	var sharedKey [32]byte
	box.Precompute(&sharedKey, pub, priv)
	return SecureWriter{w, &sharedKey}
}

type SecureReadWriteCloser struct {
	sr   io.Reader
	sw   io.Writer
	conn net.Conn
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

func (srwc SecureReadWriteCloser) Close() error {
	return srwc.conn.Close()
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	myPub, myPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Println("error generating client keys", err)
		return nil, err
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Println("error dialing server", err)
		return nil, err
	}

	peerPub, err := clientHandshake(conn, myPub)
	if err != nil {
		log.Println("client handshake failed", err)
		return nil, err
	}

	srwc := NewSecureReadWriteCloser(conn, myPriv, peerPub)

	return srwc, nil
}

func clientHandshake(conn net.Conn, pub *[32]byte) (*[32]byte, error) {
	// write my pub key to connection
	_, err := fmt.Fprintf(conn, string(pub[:32]))
	if err != nil {
		return nil, err
	}

	// read server pub key from connection
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		return nil, err
	}

	var peerPub [32]byte
	copy(peerPub[:], buf[0:32])
	return &peerPub, nil
}

func serverHandshake(conn net.Conn, pub *[32]byte) (*[32]byte, error) {
	// read client pub key from connection
	buf := make([]byte, 1024)
	_, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	// write my pub key to connection
	_, err = fmt.Fprintf(conn, string(pub[:32]))
	if err != nil {
		return nil, err
	}

	var peerPub [32]byte
	copy(peerPub[:], buf[0:32])
	return &peerPub, nil
}

// Create new connection from rwc.
func newConn(rwc net.Conn, priv, pub *[32]byte) *conn {
	c := new(conn)
	c.remoteAddr = rwc.RemoteAddr().String()
	c.rwc = rwc
	c.srwc = NewSecureReadWriteCloser(rwc, priv, pub)
	return c
}

// A conn represents the server side of an HTTP connection.
type conn struct {
	remoteAddr string   // network address of remote side
	rwc        net.Conn // i/o connection
	srwc       io.ReadWriteCloser
}

// Serve starts a secure echo server on the given listener.
// http://golang.org/src/net/http/server.go?s=51504:51550#L1714
// http://loige.co/simple-echo-server-written-in-go-dockerized/
func Serve(l net.Listener) error {
	myPub, myPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		peerPub, err := serverHandshake(conn, myPub)
		if err != nil {
			continue
		}
		c := newConn(conn, myPriv, peerPub)
		go c.serve()
	}

	return err
}

// Serve a new connection.
func (c *conn) serve() {
	for {
		// read from the client connection
		buf := make([]byte, 2048)
		n, err := c.srwc.Read(buf)
		if err != nil {
			if err == io.EOF {
				//println("conn read EOF")
				break // Don't reply
			} else if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				//println("conn read timeout")
				break // Don't reply
			} else {
				//println("conn read failed: ", err)
				break
			}
		}

		// write to the client connection
		_, err = fmt.Fprintf(c.srwc, string(buf[:n]))
		if err != nil {
			println("conn write failed", err)
			break
		}
	}
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
