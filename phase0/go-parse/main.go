package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func load(path string) *x509.Certificate {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		fmt.Printf("%s: PARSE FAIL: %v\n", path, err)
		os.Exit(0)
	}
	fmt.Printf("%s: parsed. sigAlg=%v pubKeyAlg=%v\n", path, c.SignatureAlgorithm, c.PublicKeyAlgorithm)
	return c
}

func main() {
	for _, chain := range []string{"mldsa65", "mixed", "catalyst"} {
		fmt.Printf("--- chain: %s ---\n", chain)
		var leaf, inter, root *x509.Certificate
		if chain == "catalyst" {
			leaf = load("chains/catalyst/leaf.crt")
			inter = load("chains/ecdsa/int.crt")
			root = load("chains/ecdsa/root.crt")
		} else {
			leaf = load("chains/" + chain + "/leaf.crt")
			inter = load("chains/" + chain + "/int.crt")
			root = load("chains/" + chain + "/root.crt")
		}
		roots := x509.NewCertPool()
		roots.AddCert(root)
		ints := x509.NewCertPool()
		ints.AddCert(inter)
		_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: ints, DNSName: ""})
		if err != nil {
			fmt.Printf("verify: FAIL: %v\n", err)
		} else {
			fmt.Println("verify: OK")
		}
	}
}
