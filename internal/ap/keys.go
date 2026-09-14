package ap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateKeyPair creates an RSA-2048 keypair, PEM-encoded. RSA because
// draft-cavage HTTP Signatures (what Graft and every mainstream
// ActivityPub implementation use) expects it.
func GenerateKeyPair() (privatePEM, publicPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate rsa key: %w", err)
	}
	priv := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("marshal public key: %w", err)
	}
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	return string(priv), string(pub), nil
}

// ParsePrivateKey decodes a PKCS#1 PEM-encoded RSA private key.
func ParsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ParsePublicKey decodes a PKIX PEM-encoded public key, as found in a
// remote actor's publicKeyPem field.
func ParsePublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}
	return rsaKey, nil
}
