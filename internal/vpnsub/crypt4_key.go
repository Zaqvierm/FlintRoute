package vpnsub

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
)

// crypt4PrivateKeyDERBase64 is the protocol key used for Happ crypt4 links.
// It is kept in this adapter instead of being mixed into the subscription
// pipeline. The value is protocol material, not a per-user subscription
// credential. A deployment-specific key file may still override it.
const crypt4PrivateKeyDERBase64 = "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"

func embeddedCrypt4Key() *rsa.PrivateKey {
	der, err := base64.StdEncoding.DecodeString(crypt4PrivateKeyDERBase64)
	if err != nil {
		return nil
	}
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil || key.Size() != 512 {
		return nil
	}
	return key
}
