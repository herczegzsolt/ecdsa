# Generic ecdsa for golang

Golang native implementation of Elliptic Curves - including secp256k1.

---

## Features

- Based on the now-deprecated native `crypto/elliptic` package, no external dependency at all
- Support for any Weierstrass curve y² = x³ + ax + b including secp256k1, P224, P256, P384, and P521
- Suitable for use with tinygo without any hardware acceleration

## Motivation

Golang's `crypto/elliptic` and `crypto/ecdsa` has been deprecated for all but NIST-recommended
curves (P224, P256, P384, P521), and lacks implementation of y² = x³ + ax + b curves where a != -3.

For a general curve like the popular secp256k1, one would have to rely on external packages, or
deprecated codepaths in case of a = 3. This package aims to provide a general implementation of
short-form Weierstrass curves without introducing further dependencies or build constraints.[^1]
[^1]: This package does depend on golang.org/x repositories, which are part of the Go Project but
are outside the main Go tree.

Note that this package uses `math/big`, which does not provide any timing guarantees, therefore
it is not suitable for use when timing attacks are possible.

Quoting the go standard library:

> [This package ...] is not guaranteed to provide any security property

## Credits

Majority of the ECDSA implementation is directly reused from the Go Standard Library.
Support for a != -3 curves is based on the work of [dustinxie](https://github.com/dustinxie).
Packing and maintenance is done by [herczegzsolt](https://github.com/herczegzsolt).
