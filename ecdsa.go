// Copyright (c) 2026 Multiple Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as
// defined in FIPS 186-3.
//
// This implementation derives the nonce from an AES-CTR CSPRNG keyed by:
//
// SHA2-512(priv.D || entropy || hash)[:32]
//
// The CSPRNG key is indifferentiable from a random oracle as shown in
// [Coron], the AES-CTR stream is indifferentiable from a random oracle
// under standard cryptographic assumptions (see [Larsson] for examples).
//
// References:
//
//	[Coron]
//	  https://cs.nyu.edu/~dodis/ps/merkle.pdf
//	[Larsson]
//	  https://www.nada.kth.se/kurser/kth/2D1441/semteo03/lecturenotes/assump.pdf
package ecdsa

// Further references:
//   [NSA]: Suite B implementer's guide to FIPS 186-3
//     https://apps.nsa.gov/iaarchive/library/ia-guidance/ia-solutions-for-classified/algorithm-guidance/suite-b-implementers-guide-to-fips-186-3-ecdsa.cfm
//   [SECG]: SECG, SEC1
//     http://www.secg.org/sec1-v2.pdf

import (
	"errors"
	"io"
	"math/big"
	"math/rand/v2"
)

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.2.
func randFieldElement(c Curve, rand io.Reader) (k *big.Int, err error) {
	for {
		N := c.Params().N
		b := make([]byte, (N.BitLen()+7)/8)
		if _, err = io.ReadFull(rand, b); err != nil {
			return
		}
		if excess := len(b)*8 - N.BitLen(); excess > 0 {
			b[0] >>= excess
		}
		k = new(big.Int).SetBytes(b)
		if k.Sign() != 0 && k.Cmp(N) < 0 {
			return
		}
	}
}

// hashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func hashToInt(hash []byte, c Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

var errZeroParam = errors.New("zero parameter")

// SignASN1 signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the ASN.1 encoded signature. The security of the private key
// depends on the entropy of csprng.
func SignASN1(csprng io.Reader, priv *PrivateKey, hash []byte) ([]byte, error) {
	r, s, err := Sign(csprng, priv, hash)
	if err != nil {
		return nil, err
	}

	return encodeSignature(r.Bytes(), s.Bytes())
}

// sign is the actual implementation of ECDSA signing via math.big functions
func sign(priv *PrivateKey, csprng io.Reader, hash []byte) (r, s *big.Int, err error) {
	c := priv.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	var k, kInv *big.Int
	for {
		for {
			k, err = randFieldElement(c, csprng)
			if err != nil {
				r = nil
				return
			}

			kInv = new(big.Int).ModInverse(k, N)

			r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
			r.Mod(r, N)
			if r.Sign() != 0 && kInv != nil {
				break
			}
		}

		e := hashToInt(hash, c)
		s = new(big.Int).Mul(priv.D, r)
		s.Add(s, e)
		s.Mul(s, kInv)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			break
		}
	}
	return
}

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the signature as a pair of integers. Most applications should use
// [SignASN1] instead of dealing directly with r, s.
func Sign(csprng io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	maybeReadByte(csprng)

	// A cheap version of hedged signatures
	var seed [32]byte
	if _, err := io.ReadFull(csprng, seed[:]); err != nil {
		return nil, nil, err
	}
	for i, b := range priv.D.Bytes() {
		seed[i%32] ^= b
	}
	for i, b := range hash {
		seed[i%32] ^= b
	}
	csprng = rand.NewChaCha8(seed)

	r, s, err = sign(priv, csprng, hash)
	if err != nil {
		return nil, nil, err
	}

	return r, s, nil
}

func GenerateKey(c Curve, rand io.Reader) (*PrivateKey, error) {
	k, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}

	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

// PublicKey represents an ECDSA public key.
type PublicKey struct {
	Curve Curve

	// X, Y are the coordinates of the public key point.
	//
	// Modifying the raw coordinates can produce invalid keys
	X, Y *big.Int
}

// Equal reports whether pub and x have the same value.
//
// Two keys are only considered to have the same value if they have the same Curve value.
func (pub *PublicKey) Equal(x *PublicKey) bool {
	return bigIntEqual(pub.X, x.X) && bigIntEqual(pub.Y, x.Y) && pub.Curve.Equal(x.Curve)
}

// PrivateKey represents an ECDSA private key.
type PrivateKey struct {
	PublicKey

	// D is the private scalar value.
	//
	// Modifying the raw value can produce invalid keys.
	D *big.Int
}

// Equal reports whether priv and x have the same value.
//
// Two keys are only considered to have the same value if they have the same Curve value.
func (priv *PrivateKey) Equal(x *PrivateKey) bool {
	return bigIntEqual(priv.D, x.D) && priv.PublicKey.Equal(&x.PublicKey)
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid. Most applications should
// use VerifyASN1 instead of dealing directly with r, s.
func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	// SEC 1, Version 2.0, Section 4.1.4
	e := hashToInt(hash, c)
	w := new(big.Int).ModInverse(s, N)

	u1 := e.Mul(e, w)
	u1.Mod(u1, N)
	u2 := w.Mul(r, w)
	u2.Mod(u2, N)

	x1, y1 := c.ScalarBaseMult(u1.Bytes())
	x2, y2 := c.ScalarMult(pub.X, pub.Y, u2.Bytes())
	x, y := c.Add(x1, y1, x2, y2)

	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

// VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
func VerifyASN1(pub *PublicKey, hash, sig []byte) bool {
	rBytes, sBytes, err := parseSignature(sig)
	if err != nil {
		return false
	}
	r, s := new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes)

	return Verify(pub, hash, r, s)
}
