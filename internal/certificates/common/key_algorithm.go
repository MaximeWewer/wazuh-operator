/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certcommon

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// KeyAlgorithm represents the algorithm used for key generation
type KeyAlgorithm string

const (
	// KeyAlgorithmRSA uses RSA for key generation (default)
	KeyAlgorithmRSA KeyAlgorithm = "RSA"
	// KeyAlgorithmECDSA uses ECDSA for key generation
	KeyAlgorithmECDSA KeyAlgorithm = "ECDSA"
)

// ECDSACurve represents the elliptic curve used for ECDSA
type ECDSACurve string

const (
	// ECDSACurveP256 uses the P-256 curve (also known as secp256r1 or prime256v1)
	// Provides ~128 bits of security
	ECDSACurveP256 ECDSACurve = "P256"
	// ECDSACurveP384 uses the P-384 curve (also known as secp384r1)
	// Provides ~192 bits of security
	ECDSACurveP384 ECDSACurve = "P384"
	// ECDSACurveP521 uses the P-521 curve (also known as secp521r1)
	// Provides ~256 bits of security (highest level)
	ECDSACurveP521 ECDSACurve = "P521"
)

// GetCurve returns the elliptic.Curve for the given ECDSACurve
func GetCurve(curve ECDSACurve) elliptic.Curve {
	switch curve {
	case ECDSACurveP521:
		return elliptic.P521()
	case ECDSACurveP384:
		return elliptic.P384()
	default:
		return elliptic.P256()
	}
}

// GeneratePrivateKey generates a private key based on the algorithm
func GeneratePrivateKey(algorithm KeyAlgorithm, keySize int, curve ECDSACurve) (crypto.PrivateKey, error) {
	switch algorithm {
	case KeyAlgorithmECDSA:
		return ecdsa.GenerateKey(GetCurve(curve), rand.Reader)
	default:
		if keySize <= 0 {
			keySize = DefaultKeySize
		}
		return rsa.GenerateKey(rand.Reader, keySize)
	}
}

// EncodePrivateKeyToPEM encodes a private key to PEM format
// Uses PKCS#8 format for ECDSA keys for OpenSearch compatibility
func EncodePrivateKeyToPEM(key crypto.PrivateKey) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}), nil
	case *ecdsa.PrivateKey:
		// Use PKCS#8 format for ECDSA keys - OpenSearch/Java requires this format
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA private key to PKCS#8: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}), nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", key)
	}
}

// ParsePrivateKeyFromPEM parses a private key from PEM data
func ParsePrivateKeyFromPEM(keyPEM []byte) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		// PKCS#8 format - can contain either RSA or ECDSA
		return x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", keyBlock.Type)
	}
}

// ConvertPrivateKeyPEMToPKCS8 converts a supported private key PEM
// (PKCS#1 RSA, SEC1 EC, or PKCS#8) to PKCS#8 PEM format.
func ConvertPrivateKeyPEMToPKCS8(keyPEM []byte) ([]byte, error) {
	privateKey, err := ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key for PKCS#8 conversion: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

// GetPublicKey extracts the public key from a private key
func GetPublicKey(key crypto.PrivateKey) crypto.PublicKey {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
