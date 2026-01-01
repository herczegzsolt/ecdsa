# Generic ecdsa for golang

Golang native implementation of Curves - including secp256k1.

---

## Features

- Based on the now-deprecated native `crypto/elliptic` package, no external dependency at all
- Support for any Weierstrass curve y² = x³ + ax + b including secp256k1, P224, P256, P384, and P521
- Automatic fallback to native `crypto/ecdsa` implementation (optional)

## Motivation

Golang's `crypto/elliptic` and `crypto/ecdsa` has been deprecated for all but NIST-recommended
curves (P224, P256, P384, P521), and lacks implementation of y² = x³ + ax + b curves where a != -3.

For a general curve like the popular secp256k1, one would have to rely on external packages, or
deprecated codepaths in case of a = 3

This package aims to provide a general implementation of short-form Weierstrass curves with an
optional automatic fallback to the native implementation whenever possible.

No external dependency is introduced.

Note that this package relies on `math/big`, which provides no timing guarantees. This package is
not suitable for use if a timing side-channel attack is a concern.

Quoting the go standard library: [This package ...] is not guaranteed to provide any security property
