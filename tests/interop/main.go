package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/nats-io/nkeys"
)

func main() {
	mode := os.Args[1]
	switch mode {
	case "pub": // seed on argv → print public key
		kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(os.Args[2])))
		must(err)
		pub, err := kp.PublicKey()
		must(err)
		fmt.Println(pub)
	case "sign": // seed, file → base64url raw signature
		kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(os.Args[2])))
		must(err)
		data, err := os.ReadFile(os.Args[3])
		must(err)
		sig, err := kp.Sign(data)
		must(err)
		fmt.Println(base64.RawURLEncoding.EncodeToString(sig))
	case "xgen": // create curve keys → seed + pub on two lines
		kp, err := nkeys.CreateCurveKeys()
		must(err)
		seed, err := kp.Seed()
		must(err)
		pub, err := kp.PublicKey()
		must(err)
		fmt.Println(string(seed))
		fmt.Println(pub)
	case "xpub": // curve seed → pub
		kp, err := nkeys.FromCurveSeed([]byte(strings.TrimSpace(os.Args[2])))
		must(err)
		pub, err := kp.PublicKey()
		must(err)
		fmt.Println(pub)
	case "jwt": // creds file → JWT
		data, err := os.ReadFile(os.Args[2])
		must(err)
		jwt, err := nkeys.ParseDecoratedJWT(data)
		must(err)
		fmt.Println(jwt)
	case "nkey": // creds file → public key of the parsed nkey
		data, err := os.ReadFile(os.Args[2])
		must(err)
		kp, err := nkeys.ParseDecoratedNKey(data)
		must(err)
		pub, err := kp.PublicKey()
		must(err)
		fmt.Println(pub)
	case "usernkey": // creds file → public key, user-only
		data, err := os.ReadFile(os.Args[2])
		must(err)
		kp, err := nkeys.ParseDecoratedUserNKey(data)
		must(err)
		pub, err := kp.PublicKey()
		must(err)
		fmt.Println(pub)
	case "priv": // seed → encoded private key ('P…')
		kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(os.Args[2])))
		must(err)
		priv, err := kp.PrivateKey()
		must(err)
		fmt.Println(string(priv))
	case "xseal": // senderSeed, recipientPub, nonceHex|rand, msgB64 → b64 ciphertext
		kp, err := nkeys.FromCurveSeed([]byte(strings.TrimSpace(os.Args[2])))
		must(err)
		msg, err := base64.StdEncoding.DecodeString(os.Args[5])
		must(err)
		var out []byte
		if os.Args[4] == "rand" {
			out, err = kp.Seal(msg, strings.TrimSpace(os.Args[3]))
		} else {
			nonce, e := hex.DecodeString(os.Args[4])
			must(e)
			out, err = kp.SealWithRand(msg, strings.TrimSpace(os.Args[3]), bytes.NewReader(nonce))
		}
		must(err)
		fmt.Println(base64.StdEncoding.EncodeToString(out))
	case "xopen": // recipientSeed, senderPub, cipherB64 → b64 plaintext
		kp, err := nkeys.FromCurveSeed([]byte(strings.TrimSpace(os.Args[2])))
		must(err)
		ct, err := base64.StdEncoding.DecodeString(os.Args[4])
		must(err)
		msg, err := kp.Open(ct, strings.TrimSpace(os.Args[3]))
		must(err)
		fmt.Println(base64.StdEncoding.EncodeToString(msg))
	case "verify": // pub, file, b64url-sig
		kp, err := nkeys.FromPublicKey(strings.TrimSpace(os.Args[2]))
		must(err)
		data, err := os.ReadFile(os.Args[3])
		must(err)
		sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(os.Args[4]))
		must(err)
		must(kp.Verify(data, sig))
		fmt.Println("GO-VERIFY-OK")
	}
}
func must(err error) { if err != nil { fmt.Fprintln(os.Stderr, "ERR:", err); os.Exit(1) } }
