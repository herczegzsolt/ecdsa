package ecdsa

import (
	"math/big"
	"sync"
)

var initonce sync.Once
var p224 *GenericCurve
var p256 *GenericCurve
var p384 *GenericCurve
var p521 *GenericCurve
var p256k1 *GenericCurve

func initAll() {
	initP224()
	initP256()
	initP384()
	initP521()
	initSecp256k1()
}

func initP224() {
	// See FIPS 186-3, section D.2.2
	p224 = new(GenericCurve)
	p224.p.Name = "P-224"
	p224.p.P, _ = new(big.Int).SetString("26959946667150639794667015087019630673557916260026308143510066298881", 10)
	p224.p.N, _ = new(big.Int).SetString("26959946667150639794667015087019625940457807714424391721682722368061", 10)
	p224.p.B, _ = new(big.Int).SetString("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16)
	p224.p.Gx, _ = new(big.Int).SetString("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 16)
	p224.p.Gy, _ = new(big.Int).SetString("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16)
	p224.p.A = big.NewInt(-3)
	p224.p.BitSize = 224
}

// P224 returns a Curve which implements NIST P-224 (FIPS 186-3, section D.2.2),
// also known as secp224r1. The CurveParams.Name of this Curve is "P-224".
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations may not use constant-time algorithms.
func P224() Curve {
	initonce.Do(initAll)
	return p224
}

func initP256() {
	// See FIPS 186-3, section D.2.3
	p256 = new(GenericCurve)
	p256.p.Name = "P-256"
	p256.p.P, _ = new(big.Int).SetString("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)
	p256.p.N, _ = new(big.Int).SetString("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10)
	p256.p.B, _ = new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
	p256.p.Gx, _ = new(big.Int).SetString("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
	p256.p.Gy, _ = new(big.Int).SetString("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
	p256.p.A = big.NewInt(-3)
	p256.p.BitSize = 256
}

// P256 returns a Curve which implements NIST P-256 (FIPS 186-3, section D.2.3),
// also known as secp256r1 or prime256v1. The CurveParams.Name of this Curve is "P-256".
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations may not use constant-time algorithms.
func P256() Curve {
	initonce.Do(initAll)
	return p256
}

func initP384() {
	// See FIPS 186-3, section D.2.4
	p384 = new(GenericCurve)
	p384.p.Name = "P-384"
	p384.p.P, _ = new(big.Int).SetString("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319", 10)
	p384.p.N, _ = new(big.Int).SetString("39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643", 10)
	p384.p.B, _ = new(big.Int).SetString("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16)
	p384.p.Gx, _ = new(big.Int).SetString("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16)
	p384.p.Gy, _ = new(big.Int).SetString("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16)
	p384.p.A = big.NewInt(-3)
	p384.p.BitSize = 384
}

// P384 returns a Curve which implements NIST P-384 (FIPS 186-3, section D.2.4),
// also known as secp384r1. The CurveParams.Name of this Curve is "P-384".
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations may not use constant-time algorithms.
func P384() Curve {
	initonce.Do(initAll)
	return p384
}

func initP521() {
	// See FIPS 186-3, section D.2.5
	p521 = new(GenericCurve)
	p521.p.Name = "P-521"
	p521.p.P, _ = new(big.Int).SetString("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151", 10)
	p521.p.N, _ = new(big.Int).SetString("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449", 10)
	p521.p.B, _ = new(big.Int).SetString("051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16)
	p521.p.Gx, _ = new(big.Int).SetString("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16)
	p521.p.Gy, _ = new(big.Int).SetString("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16)
	p521.p.A = big.NewInt(-3)
	p521.p.BitSize = 521
}

// P521 returns a Curve which implements NIST P-521 (FIPS 186-3, section D.2.5),
// also known as secp521r1. The CurveParams.Name of this Curve is "P-521".
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations may not use constant-time algorithms.
func P521() Curve {
	initonce.Do(initAll)
	return p521
}

func initSecp256k1() {
	// See https://www.secg.org/sec2-v2.pdf, section 2.4.1
	// curve equation y² = x³ + 7
	p256k1 = new(GenericCurve)
	p256k1.p.Name = "P-256k1"
	p256k1.p.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	p256k1.p.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	p256k1.p.B = big.NewInt(7)
	p256k1.p.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	p256k1.p.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	p256k1.p.A = big.NewInt(0)
	p256k1.p.BitSize = 256
}

// P256k1 returns a Curve which implements secp256k1 (https://www.secg.org/sec2-v2.pdf, section 2.4.1),
// The CurveParams.Name of this Curve is "P-256k1".
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations do not use constant-time algorithms.
func P256k1() Curve {
	initonce.Do(initAll)
	return p256k1
}
