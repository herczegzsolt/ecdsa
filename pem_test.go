// Copyright 2026 Multiple Authors
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdsa

import (
	"crypto/rand"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// opensslSecp256k1PrivateKeyPEM was generated with:
//
//	openssl ecparam -name secp256k1 -genkey -out k1.pem
//
// It includes the leading "EC PARAMETERS" block that OpenSSL emits by
// default, which must be skipped by ParsePrivateKeyPEM.
const opensslSecp256k1PrivateKeyPEM = `-----BEGIN EC PARAMETERS-----
BgUrgQQACg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIMSFAOSFsmsGubwcKfOt1eLI9Q6GjXwuLwu124oCIjV2oAcGBSuBBAAK
oUQDQgAEj0NAFwQO42V1UoNpLhedN2AEK83mKhEhHyivnL8l5F6UAtewFQGoQXrr
LIbBwPyNLAskn3rLfzV+dUzkHoPl+Q==
-----END EC PRIVATE KEY-----
`

// opensslSecp256k1PublicKeyPEM is the public key matching
// opensslSecp256k1PrivateKeyPEM, generated with:
//
//	openssl ec -in k1.pem -pubout -out k1_pub.pem
const opensslSecp256k1PublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEj0NAFwQO42V1UoNpLhedN2AEK83mKhEh
HyivnL8l5F6UAtewFQGoQXrrLIbBwPyNLAskn3rLfzV+dUzkHoPl+Q==
-----END PUBLIC KEY-----
`

// opensslP256PrivateKeyPEM was generated with:
//
//	openssl ecparam -name prime256v1 -genkey -noout -out p256.pem
const opensslP256PrivateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILN7HICGX6NmrPybQHV3R3AkzeHTXyQYBNh/lMvRwtEEoAoGCCqGSM49
AwEHoUQDQgAEUpzg4FAmH5KZGkuDRRVJUD/1LmbDJslepzUKYC50EbtSmnkAVrL+
dT+F54E6fWKocY7n/HAYBAZkCZ0iieuTXw==
-----END EC PRIVATE KEY-----
`

// opensslP256PublicKeyPEM is the public key matching opensslP256PrivateKeyPEM.
const opensslP256PublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUpzg4FAmH5KZGkuDRRVJUD/1LmbD
JslepzUKYC50EbtSmnkAVrL+dT+F54E6fWKocY7n/HAYBAZkCZ0iieuTXw==
-----END PUBLIC KEY-----
`

func curvesForPEMTest() []struct {
	c   Curve
	tag string
} {
	return []struct {
		c   Curve
		tag string
	}{
		{P224(), "p224"},
		{P256(), "p256"},
		{P384(), "p384"},
		{P521(), "p521"},
		{P256k1(), "p256k1"},
	}
}

func testPrivateKeyPEMRoundTrip(t *testing.T, c Curve, tag string) {
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("%s: GenerateKey: %s", tag, err)
	}

	der, err := priv.MarshalDER()
	if err != nil {
		t.Fatalf("%s: MarshalECPrivateKey: %s", tag, err)
	}
	got, err := ParseDERPrivateKey(der)
	if err != nil {
		t.Fatalf("%s: ParseECPrivateKey: %s", tag, err)
	}
	if !priv.Equal(got) {
		t.Errorf("%s: round-tripped private key (DER) does not match original", tag)
	}

	pemBytes, err := priv.MarshalPEM()
	if err != nil {
		t.Fatalf("%s: MarshalPEM: %s", tag, err)
	}
	if !strings.Contains(string(pemBytes), "-----BEGIN EC PRIVATE KEY-----") {
		t.Errorf("%s: PEM output missing EC PRIVATE KEY header:\n%s", tag, pemBytes)
	}
	got, err = ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("%s: ParsePrivateKeyPEM: %s", tag, err)
	}
	if !priv.Equal(got) {
		t.Errorf("%s: round-tripped private key (PEM) does not match original", tag)
	}
}

func TestPrivateKeyPEMRoundTrip(t *testing.T) {
	for _, tc := range curvesForPEMTest() {
		testPrivateKeyPEMRoundTrip(t, tc.c, tc.tag)
	}
}

func testPublicKeyPEMRoundTrip(t *testing.T, c Curve, tag string) {
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("%s: GenerateKey: %s", tag, err)
	}
	pub := &priv.PublicKey

	der, err := pub.MarshalDER()
	if err != nil {
		t.Fatalf("%s: MarshalPKIXPublicKey: %s", tag, err)
	}
	got, err := ParseDERPublicKey(der)
	if err != nil {
		t.Fatalf("%s: ParsePKIXPublicKey: %s", tag, err)
	}
	if !pub.Equal(got) {
		t.Errorf("%s: round-tripped public key (DER) does not match original", tag)
	}

	pemBytes, err := pub.MarshalPEM()
	if err != nil {
		t.Fatalf("%s: MarshalPEM: %s", tag, err)
	}
	if !strings.Contains(string(pemBytes), "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("%s: PEM output missing PUBLIC KEY header:\n%s", tag, pemBytes)
	}
	got, err = ParsePEMPublicKey(pemBytes)
	if err != nil {
		t.Fatalf("%s: ParsePublicKeyPEM: %s", tag, err)
	}
	if !pub.Equal(got) {
		t.Errorf("%s: round-tripped public key (PEM) does not match original", tag)
	}
}

func TestPublicKeyPEMRoundTrip(t *testing.T) {
	for _, tc := range curvesForPEMTest() {
		testPublicKeyPEMRoundTrip(t, tc.c, tc.tag)
	}
}

// TestPrivateKeyPEMWithoutEmbeddedPublicKey checks that a SEC 1 ECPrivateKey
// DER structure omitting the optional [1] publicKey field is still parsed
// correctly, with the public key recomputed from the private scalar.
func TestPrivateKeyPEMWithoutEmbeddedPublicKey(t *testing.T) {
	c := P256()
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}

	der, err := priv.MarshalDER()
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %s", err)
	}

	stripped := stripEmbeddedPublicKey(t, der)

	got, err := ParseDERPrivateKey(stripped)
	if err != nil {
		t.Fatalf("ParseECPrivateKey: %s", err)
	}
	if !priv.Equal(got) {
		t.Errorf("recomputed public key does not match original")
	}
}

// stripEmbeddedPublicKey removes the optional [1] EXPLICIT publicKey field
// from a SEC 1 ECPrivateKey DER structure produced by MarshalECPrivateKey,
// which always places it as the last element of the outer SEQUENCE. It is
// parsed properly with cryptobyte, rather than searching for tag bytes,
// since the private key's raw bytes could otherwise coincidentally contain
// a byte matching the [1] tag.
func stripEmbeddedPublicKey(t *testing.T, der []byte) []byte {
	t.Helper()

	input := cryptobyte.String(der)
	var content cryptobyte.String
	if !input.ReadASN1(&content, asn1.SEQUENCE) || !input.Empty() {
		t.Fatalf("stripEmbeddedPublicKey: invalid DER")
	}

	remain := content
	var version int64
	if !remain.ReadASN1Integer(&version) {
		t.Fatalf("stripEmbeddedPublicKey: invalid version")
	}
	var privKey []byte
	if !remain.ReadASN1Bytes(&privKey, asn1.OCTET_STRING) {
		t.Fatalf("stripEmbeddedPublicKey: invalid private key")
	}
	var params cryptobyte.String
	var hasParams bool
	if !remain.ReadOptionalASN1(&params, &hasParams, explicit0) {
		t.Fatalf("stripEmbeddedPublicKey: invalid parameters")
	}

	// Everything remaining should be exactly the [1] publicKey field, since
	// MarshalECPrivateKey always writes it last.
	beforePub := len(remain)
	var pub cryptobyte.String
	var hasPub bool
	if !remain.ReadOptionalASN1(&pub, &hasPub, explicit1) {
		t.Fatalf("stripEmbeddedPublicKey: invalid public key field")
	}
	if !hasPub {
		t.Fatalf("stripEmbeddedPublicKey: no embedded public key to strip")
	}
	if !remain.Empty() {
		t.Fatalf("stripEmbeddedPublicKey: unexpected trailing data")
	}

	newContent := []byte(content)[:len(content)-beforePub]
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(newContent)
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("stripEmbeddedPublicKey: %s", err)
	}
	return out
}

// TestOpenSSLPrivateKeyPEMInterop checks that PEM files produced by OpenSSL
// (openssl ecparam -genkey), including the leading "EC PARAMETERS" block
// that OpenSSL emits by default, are parsed correctly for both secp256k1
// (the curve required by picotool) and P-256.
func TestOpenSSLPrivateKeyPEMInterop(t *testing.T) {
	cases := []struct {
		name string
		pem  string
		pub  string
		c    Curve
	}{
		{"secp256k1", opensslSecp256k1PrivateKeyPEM, opensslSecp256k1PublicKeyPEM, P256k1()},
		{"p256", opensslP256PrivateKeyPEM, opensslP256PublicKeyPEM, P256()},
	}
	for _, tc := range cases {
		priv, err := ParsePEMPrivateKey([]byte(tc.pem))
		if err != nil {
			t.Fatalf("%s: ParsePrivateKeyPEM: %s", tc.name, err)
		}
		if !priv.Curve.Equal(tc.c) {
			t.Errorf("%s: unexpected curve", tc.name)
		}
		if !tc.c.IsOnCurve(priv.X, priv.Y) {
			t.Errorf("%s: parsed public key is not on curve", tc.name)
		}

		pub, err := ParsePEMPublicKey([]byte(tc.pub))
		if err != nil {
			t.Fatalf("%s: ParsePublicKeyPEM: %s", tc.name, err)
		}
		if !priv.PublicKey.Equal(pub) {
			t.Errorf("%s: private key's public part does not match standalone public key PEM", tc.name)
		}

		// Round-trip through this package's own marshalers and make sure
		// OpenSSL's key material survives unchanged.
		der, err := priv.MarshalDER()
		if err != nil {
			t.Fatalf("%s: MarshalECPrivateKey: %s", tc.name, err)
		}
		reparsed, err := ParseDERPrivateKey(der)
		if err != nil {
			t.Fatalf("%s: ParseECPrivateKey: %s", tc.name, err)
		}
		if !priv.Equal(reparsed) {
			t.Errorf("%s: re-marshaled key does not match", tc.name)
		}

		// Exercise sign/verify with the OpenSSL-provided key to confirm the
		// scalar and point were parsed correctly (i.e. this is a functional
		// key, not just structurally valid ASN.1).
		hash := []byte("picotool interop test")
		r, s, err := Sign(rand.Reader, priv, hash)
		if err != nil {
			t.Fatalf("%s: Sign: %s", tc.name, err)
		}
		if !Verify(&priv.PublicKey, hash, r, s) {
			t.Errorf("%s: Verify failed for signature made with OpenSSL-provided key", tc.name)
		}
	}
}

func TestParseECPrivateKeyErrors(t *testing.T) {
	priv, err := GenerateKey(P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	der, err := priv.MarshalDER()
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %s", err)
	}

	if _, err := ParseDERPrivateKey(nil); err == nil {
		t.Error("expected error for empty input")
	}
	if _, err := ParseDERPrivateKey(der[:len(der)-1]); err == nil {
		t.Error("expected error for truncated input")
	}
	if _, err := ParseDERPrivateKey(append(append([]byte{}, der...), 0x00)); err == nil {
		t.Error("expected error for trailing garbage")
	}
}

func TestParseDERPrivateKeyRejectsMismatchedPublicKey(t *testing.T) {
	first, err := GenerateKey(P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateKey(P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	byteLen := (first.Curve.Params().N.BitLen() + 7) / 8
	privateKey := first.D.FillBytes(make([]byte, byteLen))
	publicKey := Marshal(second.Curve, second.X, second.Y)
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1OctetString(privateKey)
		b.AddASN1(explicit0, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidNamedCurveP256)
		})
		b.AddASN1(explicit1, func(b *cryptobyte.Builder) {
			b.AddASN1BitString(publicKey)
		})
	})
	der, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseDERPrivateKey(der); err == nil {
		t.Fatal("accepted private key with mismatched embedded public key")
	}
}

func TestPrivateKeyMarshalDERValidation(t *testing.T) {
	valid, err := GenerateKey(P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateKey(P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  PrivateKey
	}{
		{
			name: "zero scalar",
			key:  PrivateKey{PublicKey: valid.PublicKey, D: new(big.Int)},
		},
		{
			name: "scalar equal to order",
			key:  PrivateKey{PublicKey: valid.PublicKey, D: new(big.Int).Set(valid.Curve.Params().N)},
		},
		{
			name: "mismatched public key",
			key:  PrivateKey{PublicKey: other.PublicKey, D: new(big.Int).Set(valid.D)},
		},
		{
			name: "invalid public point",
			key: PrivateKey{
				PublicKey: PublicKey{Curve: valid.Curve, X: big.NewInt(1), Y: big.NewInt(1)},
				D:         new(big.Int).Set(valid.D),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.key.MarshalDER(); err == nil {
				t.Fatal("MarshalDER accepted invalid private key")
			}
		})
	}
}

func TestPublicKeyMarshalDERValidation(t *testing.T) {
	curve := P256()
	tests := []struct {
		name string
		key  PublicKey
	}{
		{"point at infinity", PublicKey{Curve: curve, X: new(big.Int), Y: new(big.Int)}},
		{"off-curve point", PublicKey{Curve: curve, X: big.NewInt(1), Y: big.NewInt(1)}},
		{"negative coordinate", PublicKey{Curve: curve, X: big.NewInt(-1), Y: big.NewInt(1)}},
		{"coordinate outside field", PublicKey{Curve: curve, X: new(big.Int).Set(curve.Params().P), Y: big.NewInt(1)}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.key.MarshalDER(); err == nil {
				t.Fatal("MarshalDER accepted invalid public key")
			}
		})
	}
}

func TestParsePKIXPublicKeyErrors(t *testing.T) {
	priv, err := GenerateKey(P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	der, err := priv.PublicKey.MarshalDER()
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %s", err)
	}

	if _, err := ParseDERPublicKey(nil); err == nil {
		t.Error("expected error for empty input")
	}
	if _, err := ParseDERPublicKey(der[:len(der)-1]); err == nil {
		t.Error("expected error for truncated input")
	}
	if _, err := ParseDERPublicKey(append(append([]byte{}, der...), 0x00)); err == nil {
		t.Error("expected error for trailing garbage")
	}

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidPublicKeyECDSA)
			b.AddASN1ObjectIdentifier(oidNamedCurveP256)
		})
		b.AddASN1BitString([]byte{0})
	})
	infinityDER, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDERPublicKey(infinityDER); err == nil {
		t.Error("expected error for point at infinity")
	}
}

func TestParsePrivateKeyPEMNoBlock(t *testing.T) {
	if _, err := ParsePEMPrivateKey([]byte("not a pem file")); err == nil {
		t.Error("expected error for non-PEM input")
	}
	if _, err := ParsePEMPrivateKey([]byte(opensslSecp256k1PublicKeyPEM)); err == nil {
		t.Error("expected error when only a PUBLIC KEY block is present")
	}
}

func TestParsePublicKeyPEMNoBlock(t *testing.T) {
	if _, err := ParsePEMPublicKey([]byte("not a pem file")); err == nil {
		t.Error("expected error for non-PEM input")
	}
	if _, err := ParsePEMPublicKey([]byte(opensslSecp256k1PrivateKeyPEM)); err == nil {
		t.Error("expected error when only EC PRIVATE KEY/PARAMETERS blocks are present")
	}
}

func TestMarshalUnsupportedCurve(t *testing.T) {
	priv := &PrivateKey{
		PublicKey: PublicKey{Curve: nil},
	}
	if _, err := priv.MarshalDER(); err == nil {
		t.Error("expected error for nil curve")
	}
	if _, err := priv.PublicKey.MarshalDER(); err == nil {
		t.Error("expected error for nil curve")
	}
}
