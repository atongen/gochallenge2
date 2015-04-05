/*
Go Challenge 2
http://golang-challenge.com/go-challenge2/

Author: Andrew Tongen <atongen@gmail.com>
2015-04-05

In order to prevent our competitor from spying on our network,
we are going to write a small system that leverages NaCl to
establish secure communication. NaCl is a crypto system that
uses a public key for encryption and a private key for decryption.

Some helpful links:

https://github.com/ereyes01/cryptohelper/blob/master/cryptohelper.go#L31
http://pynacl.readthedocs.org/en/latest/public/
http://play.golang.org/p/ssz2AKIj_y
http://golang.org/src/net/http/server.go?s=51504:51550#L1714
http://loige.co/simple-echo-server-written-in-go-dockerized/
*/
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	myPub, myPriv, err := GenerateKey()
	if err != nil {
		return nil, err
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	peerPub, err := clientHandshake(conn, myPub)
	if err != nil {
		return nil, err
	}

	srwc := NewSecureReadWriteCloser(conn, myPriv, peerPub)

	return srwc, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	myPub, myPriv, err := GenerateKey()
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

// A conn represents the server side of an secure connection.
type conn struct {
	remoteAddr string   // network address of remote side
	rwc        net.Conn // i/o connection
	srwc       io.ReadWriteCloser
}

// Serve a new connection.
func (c *conn) serve() {
	for {
		// read from the client connection
		buf := make([]byte, 2048)
		n, err := c.srwc.Read(buf)
		if err != nil {
			if err == io.EOF {
				break // Don't reply
			} else if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				break // Don't reply
			} else {
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
