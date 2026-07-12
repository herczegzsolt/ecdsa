// Copyright 2026 Multiple Authors
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdsa

// This file adds encoding and decoding of PrivateKey and PublicKey to and
// from the standard DER structures used for elliptic curve keys, wrapped in
// PEM. These are the formats produced and consumed by OpenSSL (e.g.
// `openssl ecparam -genkey`) and required by tools such as the Raspberry Pi
// Pico's picotool (https://github.com/raspberrypi/picotool) for secp256k1
// secure-boot signing keys.

import (
	stdasn1 "encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// PEM block types used by MarshalPEM and understood by ParsePrivateKeyPEM / ParsePublicKeyPEM.
// Matches openssl ecparam and openssl ec behavior.
const (
	pemTypeECPrivateKey = "EC PRIVATE KEY"
	pemTypePublicKey    = "PUBLIC KEY"
)

var (
	// id-ecPublicKey, see RFC 5480.
	oidPublicKeyECDSA = stdasn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	// Named curve OIDs, see SEC 2 and RFC 5480.
	oidNamedCurveP224   = stdasn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256   = stdasn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384   = stdasn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521   = stdasn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidNamedCurveP256k1 = stdasn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

// oidFromCurve returns the OID for one of the supported curves
func oidFromCurve(curve Curve) (stdasn1.ObjectIdentifier, bool) {
	switch curve.Params().Name {
	case "P-224":
		return oidNamedCurveP224, true
	case "P-256":
		return oidNamedCurveP256, true
	case "P-384":
		return oidNamedCurveP384, true
	case "P-521":
		return oidNamedCurveP521, true
	case "P-256k1":
		return oidNamedCurveP256k1, true
	default:
		return nil, false
	}
}

// curveFromOID returns the curve identified by a supported OID.
func curveFromOID(oid stdasn1.ObjectIdentifier) (Curve, bool) {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return P224(), true
	case oid.Equal(oidNamedCurveP256):
		return P256(), true
	case oid.Equal(oidNamedCurveP384):
		return P384(), true
	case oid.Equal(oidNamedCurveP521):
		return P521(), true
	case oid.Equal(oidNamedCurveP256k1):
		return P256k1(), true
	default:
		return nil, false
	}
}

// explicit0 and explicit1 are the context-specific, constructed tags used by
// RFC 5915 for the ECPrivateKey "parameters" ([0]) and "publicKey" ([1])
// fields.
var (
	explicit0 = asn1.Tag(0).ContextSpecific().Constructed()
	explicit1 = asn1.Tag(1).ContextSpecific().Constructed()
)

func validatePublicKey(pub *PublicKey) error {
	if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil {
		return errors.New("ecdsa: invalid public key")
	}
	p := pub.Curve.Params().P
	if pub.X.Sign() < 0 || pub.Y.Sign() < 0 || pub.X.Cmp(p) >= 0 || pub.Y.Cmp(p) >= 0 ||
		(pub.X.Sign() == 0 && pub.Y.Sign() == 0) || !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return errors.New("ecdsa: invalid public key point")
	}
	return nil
}

// MarshalDER encodes priv into a SEC 1, ASN.1 DER "ECPrivateKey" structure (RFC 5915).
func (priv *PrivateKey) MarshalDER() ([]byte, error) {
	if priv.Curve == nil || priv.D == nil || priv.X == nil || priv.Y == nil {
		return nil, errors.New("ecdsa: invalid private key")
	}
	oid, ok := oidFromCurve(priv.Curve)
	if !ok {
		return nil, errors.New("ecdsa: unsupported elliptic curve")
	}

	if priv.D.Sign() <= 0 || priv.D.Cmp(priv.Curve.Params().N) >= 0 {
		return nil, errors.New("ecdsa: invalid private key value")
	}
	if err := validatePublicKey(&priv.PublicKey); err != nil {
		return nil, err
	}
	x, y := priv.Curve.ScalarBaseMult(priv.D.Bytes())
	if x == nil || y == nil || !bigIntEqual(priv.X, x) || !bigIntEqual(priv.Y, y) {
		return nil, errors.New("ecdsa: embedded public key does not match private scalar")
	}

	byteLen := (priv.Curve.Params().N.BitLen() + 7) / 8
	privateKey := make([]byte, byteLen)
	priv.D.FillBytes(privateKey)

	publicKey := Marshal(priv.Curve, priv.X, priv.Y)

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1) // ecPrivkeyVer1
		b.AddASN1OctetString(privateKey)
		b.AddASN1(explicit0, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid)
		})
		b.AddASN1(explicit1, func(b *cryptobyte.Builder) {
			b.AddASN1BitString(publicKey)
		})
	})
	return b.Bytes()
}

// ParseDERPrivateKey parses an EC private key in SEC 1, ASN.1 DER form.
//
// The "parameters" field, which carries the named curve, must be present;
// this implementation does not support curve parameters supplied out of
// band (as can happen when an ECPrivateKey is embedded in a PKCS#8
// structure).
// The "publicKey" field is optional: if absent, the public key
// is recomputed from the private scalar.
func ParseDERPrivateKey(der []byte) (*PrivateKey, error) {
	input := cryptobyte.String(der)
	var inner cryptobyte.String
	if !input.ReadASN1(&inner, asn1.SEQUENCE) || !input.Empty() {
		return nil, errors.New("ecdsa: invalid ASN.1 EC private key")
	}

	var version int64
	if !inner.ReadASN1Integer(&version) {
		return nil, errors.New("ecdsa: invalid ASN.1 EC private key")
	}
	if version != 1 {
		return nil, fmt.Errorf("ecdsa: unsupported EC private key version %d", version)
	}

	var privateKey []byte
	if !inner.ReadASN1Bytes(&privateKey, asn1.OCTET_STRING) {
		return nil, errors.New("ecdsa: invalid ASN.1 EC private key")
	}

	var params cryptobyte.String
	var hasParams bool
	if !inner.ReadOptionalASN1(&params, &hasParams, explicit0) {
		return nil, errors.New("ecdsa: invalid ASN.1 EC private key parameters")
	}
	if !hasParams {
		return nil, errors.New("ecdsa: EC private key is missing named curve parameters")
	}
	var oid stdasn1.ObjectIdentifier
	if !params.ReadASN1ObjectIdentifier(&oid) || !params.Empty() {
		return nil, errors.New("ecdsa: invalid ASN.1 EC private key parameters")
	}
	curve, ok := curveFromOID(oid)
	if !ok {
		return nil, errors.New("ecdsa: unsupported elliptic curve")
	}

	byteLen := (curve.Params().N.BitLen() + 7) / 8
	// SEC 1 requires exactly byteLen bytes, but be lenient about the
	// non-conformant leading-zero-stripped and zero-padded encodings that
	// some implementations produce, matching common practice.
	for len(privateKey) > byteLen && privateKey[0] == 0 {
		privateKey = privateKey[1:]
	}
	if len(privateKey) > byteLen {
		return nil, errors.New("ecdsa: invalid private key length")
	}

	priv := new(PrivateKey)
	priv.Curve = curve
	priv.D = new(big.Int).SetBytes(privateKey)
	if priv.D.Sign() <= 0 || priv.D.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("ecdsa: invalid private key value")
	}

	x, y := curve.ScalarBaseMult(priv.D.Bytes())
	if x == nil || y == nil {
		return nil, errors.New("ecdsa: invalid private key value")
	}

	var pubField cryptobyte.String
	var hasPub bool
	if !inner.ReadOptionalASN1(&pubField, &hasPub, explicit1) {
		return nil, errors.New("ecdsa: invalid ASN.1 EC private key embedded public key field")
	}
	if hasPub {
		var publicKey []byte
		if !pubField.ReadASN1BitStringAsBytes(&publicKey) || !pubField.Empty() {
			return nil, errors.New("ecdsa: invalid ASN.1 EC private key embedded public key field")
		}
		embeddedX, embeddedY := Unmarshal(curve, publicKey)
		if err := validatePublicKey(&PublicKey{Curve: curve, X: embeddedX, Y: embeddedY}); err != nil {
			return nil, errors.New("ecdsa: invalid embedded public key values")
		}
		if !bigIntEqual(embeddedX, x) || !bigIntEqual(embeddedY, y) {
			return nil, errors.New("ecdsa: embedded public key does not match private scalar")
		}
	}
	priv.X, priv.Y = x, y

	if !inner.Empty() {
		return nil, errors.New("ecdsa: trailing data in EC private key")
	}
	return priv, nil
}

// MarshalDER encodes pub into a PKIX, ASN.1 DER "SubjectPublicKeyInfo" structure (RFC 5480).
func (pub *PublicKey) MarshalDER() ([]byte, error) {
	if err := validatePublicKey(pub); err != nil {
		return nil, err
	}
	oid, ok := oidFromCurve(pub.Curve)
	if !ok {
		return nil, errors.New("ecdsa: unsupported elliptic curve")
	}
	publicKey := Marshal(pub.Curve, pub.X, pub.Y)

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidPublicKeyECDSA)
			b.AddASN1ObjectIdentifier(oid)
		})
		b.AddASN1BitString(publicKey)
	})
	return b.Bytes()
}

// ParseDERPublicKey parses an EC public key in PKIX, ASN.1 DER form "SubjectPublicKeyInfo"
func ParseDERPublicKey(der []byte) (*PublicKey, error) {
	input := cryptobyte.String(der)
	var inner cryptobyte.String
	if !input.ReadASN1(&inner, asn1.SEQUENCE) || !input.Empty() {
		return nil, errors.New("ecdsa: invalid ASN.1 public key")
	}

	var algorithm cryptobyte.String
	if !inner.ReadASN1(&algorithm, asn1.SEQUENCE) {
		return nil, errors.New("ecdsa: invalid ASN.1 public key algorithm")
	}
	var algOID stdasn1.ObjectIdentifier
	if !algorithm.ReadASN1ObjectIdentifier(&algOID) {
		return nil, errors.New("ecdsa: invalid ASN.1 public key algorithm")
	}
	if !algOID.Equal(oidPublicKeyECDSA) {
		return nil, errors.New("ecdsa: unsupported public key algorithm")
	}
	var curveOID stdasn1.ObjectIdentifier
	if !algorithm.ReadASN1ObjectIdentifier(&curveOID) || !algorithm.Empty() {
		return nil, errors.New("ecdsa: invalid ASN.1 EC public key parameters")
	}
	curve, ok := curveFromOID(curveOID)
	if !ok {
		return nil, errors.New("ecdsa: unsupported elliptic curve")
	}

	var publicKey []byte
	if !inner.ReadASN1BitStringAsBytes(&publicKey) || !inner.Empty() {
		return nil, errors.New("ecdsa: invalid ASN.1 public key")
	}
	x, y := Unmarshal(curve, publicKey)
	pub := &PublicKey{Curve: curve, X: x, Y: y}
	if err := validatePublicKey(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// MarshalPEM encodes priv as a PEM-encoded SEC 1 "EC PRIVATE KEY" block (RFC 5915).
// The result is in the format matching `openssl ecparam -genkey`
func (priv *PrivateKey) MarshalPEM() ([]byte, error) {
	der, err := priv.MarshalDER()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeECPrivateKey, Bytes: der}), nil
}

// ParsePEMPrivateKey decodes a PEM-encoded SEC 1 "EC PRIVATE KEY" block (RFC 5915).
//
// Data may contain other PEM blocks before the private key, any such blocks are skipped.
// (For ex: the "EC PARAMETERS" block is ignored)
func ParsePEMPrivateKey(data []byte) (*PrivateKey, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, errors.New("ecdsa: no EC PRIVATE KEY PEM block found")
		}
		if block.Type == pemTypeECPrivateKey {
			return ParseDERPrivateKey(block.Bytes)
		}
		data = rest
	}
}

// MarshalPEM encodes pub as a PEM-encoded PKIX "PUBLIC KEY" block (RFC 5480, "SubjectPublicKeyInfo")
//
// Encoded format is compatible with openssl.
func (pub *PublicKey) MarshalPEM() ([]byte, error) {
	der, err := pub.MarshalDER()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypePublicKey, Bytes: der}), nil
}

// ParsePEMPublicKey decodes a PEM-encoded PKIX "PUBLIC KEY" block (RFC 5480, "SubjectPublicKeyInfo")
//
// Any PEM blocks preceding the public key block are skipped.
func ParsePEMPublicKey(data []byte) (*PublicKey, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, errors.New("ecdsa: no PUBLIC KEY PEM block found")
		}
		if block.Type == pemTypePublicKey {
			return ParseDERPublicKey(block.Bytes)
		}
		data = rest
	}
}
