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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestConvertPrivateKeyPEMToPKCS8_RSA(t *testing.T) {
	privateKey, err := GeneratePrivateKey(KeyAlgorithmRSA, 2048, "")
	if err != nil {
		t.Fatalf("GeneratePrivateKey() error = %v", err)
	}

	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected RSA private key, got %T", privateKey)
	}

	pkcs1PEM, err := EncodePrivateKeyToPEM(rsaKey)
	if err != nil {
		t.Fatalf("EncodePrivateKeyToPEM() error = %v", err)
	}

	converted, err := ConvertPrivateKeyPEMToPKCS8(pkcs1PEM)
	if err != nil {
		t.Fatalf("ConvertPrivateKeyPEMToPKCS8() error = %v", err)
	}

	block, _ := pem.Decode(converted)
	if block == nil {
		t.Fatal("failed to decode converted key PEM")
	}
	if block.Type != "PRIVATE KEY" {
		t.Fatalf("converted PEM type = %q, want %q", block.Type, "PRIVATE KEY")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey() error = %v", err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Fatalf("expected parsed key to be RSA, got %T", parsed)
	}
}

func TestConvertPrivateKeyPEMToPKCS8_InvalidInput(t *testing.T) {
	if _, err := ConvertPrivateKeyPEMToPKCS8([]byte("invalid")); err == nil {
		t.Fatal("expected conversion to fail for invalid PEM input")
	}
}
