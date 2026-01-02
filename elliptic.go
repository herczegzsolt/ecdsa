// Copyright (c) 2026 Multiple Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdsa

// This package operates, internally, on Jacobian coordinates. For a given
// (x, y) position on the curve, the Jacobian coordinates are (x1, y1, z1)
// where x = x1/z1² and y = y1/z1³. The greatest speedups come when the whole
// calculation can be performed within the transform (as in ScalarMult and
// ScalarBaseMult). But even for Add and Double, it's faster to apply and
// reverse the transform than to operate in affine coordinates.

import (
	"math/big"
)

type Curve interface {
	// Params returns the parameters of the Curve y² = x³ + ax + b
	Params() *CurveParams

	// Equal returns whether this curve is identical to the given curve.
	Equal(c Curve) bool

	// IsOnCurve reports whether the given (x,y) lies on the curve.
	IsOnCurve(x, y *big.Int) bool

	// Add returns the sum of (x1,y1) and (x2,y2).
	Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int)

	// Double returns 2*(x,y).
	Double(x1, y1 *big.Int) (x, y *big.Int)

	// ScalarMult returns k*(x,y) where k is an integer in big-endian form.
	ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int)

	// ScalarBaseMult returns k*G, where G is the base point of the group
	// and k is an integer in big-endian form.
	ScalarBaseMult(k []byte) (x, y *big.Int)

	// Polynomial returns x³ + ax + b.
	Polynomial(x *big.Int) *big.Int
}

// CurveParams contains the parameters of an Curve y² = x³ + ax + b,
type CurveParams struct {
	P       *big.Int // the order of the underlying field
	N       *big.Int // the order of the base point
	B       *big.Int // the constant of the curve equation
	Gx, Gy  *big.Int // (x,y) of the base point
	A       *big.Int // the linear coefficient of the curve equation
	BitSize int      // the size of the underlying field
	Name    string   // the canonical name of the curve
}

// GenericCurve provides a non-constant time implementation of Curve.
type GenericCurve struct {
	p CurveParams
}

func (curve *GenericCurve) Params() *CurveParams {
	return &curve.p
}

func (curve *GenericCurve) Equal(x Curve) bool {
	xx, ok := x.(*GenericCurve)
	if !ok {
		return false
	}
	return bigIntEqual(curve.p.P, xx.p.P) &&
		bigIntEqual(curve.p.N, xx.p.N) &&
		bigIntEqual(curve.p.B, xx.p.B) &&
		bigIntEqual(curve.p.Gx, xx.p.Gx) &&
		bigIntEqual(curve.p.Gy, xx.p.Gy) &&
		bigIntEqual(curve.p.A, xx.p.A) &&
		curve.p.BitSize == xx.p.BitSize
}

// Polynomial returns x³ + ax + b.
func (curve *GenericCurve) Polynomial(x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Add(x3, curve.p.A) // x² + a
	x3.Mul(x3, x)         // x³ + ax
	x3.Add(x3, curve.p.B) // x³ + ax + b

	return x3.Mod(x3, curve.p.P)
}

// IsOnCurve returns whether the point (x, y) lies on the curve or not
// The conventional point (0, 0) returns true, unlike in the standard library.
func (curve *GenericCurve) IsOnCurve(x, y *big.Int) bool {
	if x.Sign() == 0 && y.Sign() == 0 {
		return true
	}

	// y² = x³ + ax + b
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.p.P)

	return curve.Polynomial(x).Cmp(y2) == 0
}

// zForAffine returns a Jacobian Z value for the affine point (x, y). If x and
// y are zero, it assumes that they represent the point at infinity because (0,
// 0) is not on the any of the curves handled here.
func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}

// affineFromJacobian reverses the Jacobian transform. See the comment at the
// top of the file. If the point is ∞ it returns 0, 0.
func (curve *GenericCurve) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	zinv := new(big.Int).ModInverse(z, curve.p.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)

	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, curve.p.P)
	zinvsq.Mul(zinvsq, zinv)
	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, curve.p.P)
	return
}

// Add adds 2 points
func (curve *GenericCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	return curve.affineFromJacobian(curve.addJacobian(x1, y1, z1, x2, y2, z2))
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func (curve *GenericCurve) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
	x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		return x3, y3, z3
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		return x3, y3, z3
	}

	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, curve.p.P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, curve.p.P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, curve.p.P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, curve.p.P)
	h := new(big.Int).Sub(u2, u1)
	xEqual := h.Sign() == 0
	if h.Sign() == -1 {
		h.Add(h, curve.p.P)
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i)

	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, curve.p.P)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, curve.p.P)
	r := new(big.Int).Sub(s2, s1)
	if r.Sign() == -1 {
		r.Add(r, curve.p.P)
	}
	yEqual := r.Sign() == 0
	if xEqual && yEqual {
		return curve.doubleJacobian(x1, y1, z1)
	}
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)

	x3.Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, curve.p.P)

	y3.Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, curve.p.P)

	z3.Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	z3.Mod(z3, curve.p.P)

	return x3, y3, z3
}

// Double doubles the point
func (curve *GenericCurve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	return curve.affineFromJacobian(curve.doubleJacobian(x1, y1, z1))
}

// doubleJacobian takes a point in Jacobian coordinates, (x, y, z), and
// returns its double, also in Jacobian form.
func (curve *GenericCurve) doubleJacobian(x, y, z *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
	delta := new(big.Int).Mul(z, z)
	delta.Mod(delta, curve.p.P)
	gamma := new(big.Int).Mul(y, y)
	gamma.Mod(gamma, curve.p.P)

	var alpha *big.Int
	if big.NewInt(-3).Cmp(curve.p.A) == 0 {
		// for a = -3, 3*x²+a*delta² = 3*(x+delta)*(x-delta)
		alpha = new(big.Int).Sub(x, delta)
		alpha2 := new(big.Int).Add(x, delta)
		alpha.Mul(alpha, alpha2)
		alpha2.Set(alpha)
		alpha.Lsh(alpha, 1)
		alpha.Add(alpha, alpha2)
	} else {
		// see https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl
		// M = 3*x²+a*zz², zz = z² = delta
		x2 := new(big.Int).Mul(x, x)
		alpha = new(big.Int).Lsh(x2, 1)
		alpha.Add(alpha, x2)
		if new(big.Int).Cmp(curve.p.A) != 0 {
			delta.Mul(delta, delta)
			delta.Mul(curve.p.A, delta)
			alpha.Add(alpha, delta)
		}
	}
	alpha.Mod(alpha, curve.p.P)

	beta4 := new(big.Int).Mul(x, gamma)
	beta4.Lsh(beta4, 2)
	beta4.Mod(beta4, curve.p.P)

	// X3 = alpha²-8*beta
	x3 := new(big.Int).Mul(alpha, alpha)
	beta8 := new(big.Int).Lsh(beta4, 1)
	x3.Sub(x3, beta8)
	x3.Mod(x3, curve.p.P)

	// Z3 = (Y1+Z1)²-gamma-delta = 2*Y1*Z1
	z3 := delta.Mul(y, z)
	z3.Lsh(z3, 1)
	z3.Mod(z3, curve.p.P)

	// Y3 = alpha*(4*beta-X3)-8*gamma²
	beta4.Sub(beta4, x3)
	y3 := alpha.Mul(alpha, beta4)
	gamma.Mul(gamma, gamma)
	gamma.Lsh(gamma, 3)
	y3.Sub(y3, gamma)
	y3.Mod(y3, curve.p.P)

	return x3, y3, z3
}

// ScalarMult computes scalar multiplication of a given point
func (curve *GenericCurve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	Bz := new(big.Int).SetInt64(1)
	x, y, z := new(big.Int), new(big.Int), new(big.Int)

	for _, byte := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y, z = curve.doubleJacobian(x, y, z)
			if byte&0x80 == 0x80 {
				x, y, z = curve.addJacobian(Bx, By, Bz, x, y, z)
			}
			byte <<= 1
		}
	}

	return curve.affineFromJacobian(x, y, z)
}

// ScalarBaseMult computes scalar multiplication of the base point
func (curve *GenericCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMult(curve.p.Gx, curve.p.Gy, k)
}

// Marshal converts a point on the curve into the uncompressed form specified in
// SEC 1, Version 2.0, Section 2.3.3. If the point is not on the curve, this
// function will panic. The conventional point at (0,0) is encoded as []byte{0x00}
// unlike in the standard library.
func Marshal(curve Curve, x, y *big.Int) []byte {
	panicIfNotOnCurve(curve, x, y)

	if x.Sign() == 0 && y.Sign() == 0 {
		return []byte{0x00}
	}

	byteLen := (curve.Params().BitSize + 7) / 8

	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point

	x.FillBytes(ret[1 : 1+byteLen])
	y.FillBytes(ret[1+byteLen : 1+2*byteLen])

	return ret
}

// Unmarshal converts a point, serialized by [Marshal], into an x, y pair. It is
// an error if the point is not in uncompressed form, or is not on the curve.
// On error, x, y = nil, nil.
func Unmarshal(curve Curve, data []byte) (x, y *big.Int) {
	if len(data) == 0 && data[0] == 0x00 { // point at infinity
		return big.NewInt(0), big.NewInt(0)
	}

	byteLen := (curve.Params().BitSize + 7) / 8
	if len(data) != 1+2*byteLen {
		return nil, nil
	}
	if data[0] != 4 { // uncompressed form flag
		return nil, nil
	}
	p := curve.Params().P
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, nil
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	return
}

// MarshalCompressed converts a point on the curve into the compressed form
// specified in SEC 1, Version 2.0, Section 2.3.3. If the point is not on the
// curve this function will panic. The conventional point at (0,0) is encoded as
// []byte{0x00} unlike in the standard library.
func MarshalCompressed(curve Curve, x, y *big.Int) []byte {
	panicIfNotOnCurve(curve, x, y)

	if x.Sign() == 0 && y.Sign() == 0 {
		return []byte{0x00}
	}

	byteLen := (curve.Params().BitSize + 7) / 8
	compressed := make([]byte, 1+byteLen)
	compressed[0] = byte(y.Bit(0)) | 2
	x.FillBytes(compressed[1:])
	return compressed
}

// UnmarshalCompressed converts a point, serialized by [MarshalCompressed], into
// an x, y pair. It is an error if the point is not in compressed form or is not
// on the curve. On error, x, y = nil, nil.
func UnmarshalCompressed(curve Curve, data []byte) (x, y *big.Int) {
	if len(data) == 0 && data[0] == 0x00 { // point at infinity
		return big.NewInt(0), big.NewInt(0)
	}

	byteLen := (curve.Params().BitSize + 7) / 8
	if len(data) != 1+byteLen {
		return nil, nil
	}
	if data[0] != 2 && data[0] != 3 { // compressed form
		return nil, nil
	}
	p := curve.Params().P
	x = new(big.Int).SetBytes(data[1:])
	if x.Cmp(p) >= 0 {
		return nil, nil
	}
	// y² = x³ + ax + b
	y = curve.Polynomial(x)
	y = y.ModSqrt(y, p)
	if y == nil {
		return nil, nil
	}
	if byte(y.Bit(0)) != data[0]&1 {
		y.Neg(y).Mod(y, p)
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	return
}

func panicIfNotOnCurve(curve Curve, x, y *big.Int) {
	// Unlike the go stanard library, this package choose the convention that
	// the point at infinity is represented by (0,0) is on the curve.
	if !curve.IsOnCurve(x, y) {
		panic("herczegzsolt/ecdsa: attempted operation on invalid point")
	}
}
