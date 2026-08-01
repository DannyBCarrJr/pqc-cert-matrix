// Test client for the Go runner. One test per invocation; exit 0 ok, 1 fail.
// Stdlib only, so the cell measures Go's crypto/x509 and crypto/tls as shipped.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func die(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}

func loadCert(p string) *x509.Certificate {
	b, err := os.ReadFile(p)
	if err != nil {
		die(err.Error())
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		die("no PEM block in " + p)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		die("parse: " + err.Error())
	}
	return c
}

func main() {
	switch os.Args[1] {
	case "parse":
		c := loadCert(os.Args[2])
		fmt.Printf("parsed: sigAlg=%v pubKeyAlg=%v subject=%v\n",
			c.SignatureAlgorithm, c.PublicKeyAlgorithm, c.Subject)
	case "verify":
		rootP, intP, leafP := os.Args[2], os.Args[3], os.Args[4]
		roots := x509.NewCertPool()
		roots.AddCert(loadCert(rootP))
		opts := x509.VerifyOptions{Roots: roots}
		if intP != "-" {
			ints := x509.NewCertPool()
			ints.AddCert(loadCert(intP))
			opts.Intermediates = ints
		}
		if _, err := loadCert(leafP).Verify(opts); err != nil {
			die("verify: " + err.Error())
		}
		fmt.Println("verify: OK")
	case "handshake":
		rootP, host, port := os.Args[2], os.Args[3], os.Args[4]
		roots := x509.NewCertPool()
		roots.AddCert(loadCert(rootP))
		// Go's tls.Client always verifies the hostname (ServerName); that is the
		// client's authentic behavior, so this cell includes it.
		conn, err := tls.Dial("tcp", "127.0.0.1:"+port,
			&tls.Config{ServerName: host, RootCAs: roots})
		if err != nil {
			die("handshake: " + err.Error())
		}
		st := conn.ConnectionState()
		fmt.Printf("handshake: OK version=%x cipher=%x\n", st.Version, st.CipherSuite)
		conn.Close()
	default:
		die("usage: client parse|verify|handshake ...")
	}
}
