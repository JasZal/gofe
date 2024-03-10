/*
 * Copyright (c) 2018 XLAB d.o.o
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fullysec

import (
	"math/big"

	"github.com/JasZal/gofe/data"
	"github.com/JasZal/gofe/internal/dlog"
	"github.com/JasZal/gofe/sample"
	"github.com/fentec-project/bn256"
)

// FHTAO20Params represents configuration parameters for the FHMTAO20
// scheme instance.
// SecLevel (int): The parameter defines the security assumption of the scheme,
// so called k-Lin assumption, where k is the specified SecLevel.
// VecLen (int): The length of vectors that the client encrypts.
// BoundX (int): The value by which the coordinates of encrypted vectors are bounded.
// BoundY (int): The value by which the coordinates of inner product vectors are bounded.
type FHTAO20Params struct {
	SecLevel int
	VecLen   int
	BoundX   *big.Int
	BoundY   *big.Int
}

// FHTAO20 represents a Function Hiding  Inner Product
// Encryption scheme based on the paper by Tomida, Abe and Okamoto
// "Efficient Inner Product Functional Encryption with Full-Hiding Security
// It allows  to encrypt vectors x and derive a secret key
// based on an inner product vector y so that a decryptor can
// decrypt the inner product <x,y> without
// revealing vectors x or y. The scheme is slightly modified from the
// original one to achieve a better performance. The difference is in
// storing the secret master key as matrices B, BStar, instead of matrices
// of elliptic curve elements g_1^B, g_2^BStar. This replaces elliptic curves
// operations with matrix multiplication.
//
// This struct contains the shared choice for parameters on which the
// functionality of the scheme depend.
type FHTAO20 struct {
	Params *FHTAO20Params
}

// FHTAO20SecKey represents a master secret key in FHTAO20 scheme.
type FHTAO20SecKey struct {
	BHat     data.Matrix
	BStarHat data.Matrix
}

// NewFHTAO20 configures a new instance of the scheme. See struct
// FHTAO20Params for the description of the parameters. It returns
// a new FHTAO20 instance.
func NewFHTAO20(secLevel, vecLen int, boundX, boundY *big.Int) *FHTAO20 {
	params := &FHTAO20Params{SecLevel: secLevel,
		VecLen: vecLen, BoundX: boundX, BoundY: boundY}
	return &FHTAO20{Params: params}
}

// NewFHTAO20FromParams takes configuration parameters of an existing
// FHTAO20 scheme instance, and reconstructs the scheme with the same
// configuration parameters. It returns a new FHTAO20 instance.
func NewFHTAO20FromParams(params *FHTAO20Params) *FHTAO20 {
	return &FHTAO20{
		Params: params,
	}
}

// GenerateKeys generates a pair of master secret key and public key
// for the scheme. It returns an error in case keys could not be
// generated.
func (f FHTAO20) GenerateKeys() (*FHTAO20SecKey, *bn256.GT, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), bn256.Order)
	mu, err := sampler.Sample()
	if err != nil {
		return nil, nil, err
	}

	gTMu := new(bn256.GT).ScalarBaseMult(mu)

	B, BStar, err := randomOB(2*f.Params.VecLen+2*f.Params.SecLevel+1, mu)
	if err != nil {
		return nil, nil, err
	}

	BHat := make(data.Matrix, f.Params.VecLen+f.Params.SecLevel)
	BStarHat := make(data.Matrix, f.Params.VecLen+f.Params.SecLevel)
	for j := 0; j < f.Params.VecLen+f.Params.SecLevel; j++ {
		if j < f.Params.VecLen {
			BHat[j] = B[j]
			BStarHat[j] = BStar[j]
		} else if j < f.Params.SecLevel+f.Params.VecLen {
			BHat[j] = B[j+f.Params.VecLen]
			BStarHat[j] = BStar[j+f.Params.VecLen+f.Params.SecLevel]
		}
	}

	return &FHTAO20SecKey{BHat: BHat, BStarHat: BStarHat}, gTMu, nil
}

// GenerateKeys generates a pair of master secret key and public key
// for the scheme. It returns an error in case keys could not be
// generated.
func (f FHTAO20) GenerateKeysWOS(mu *big.Int) (*FHTAO20SecKey, *bn256.GT, error) {

	gTMu := new(bn256.GT).ScalarBaseMult(mu)

	B, BStar, err := randomOB(2*f.Params.VecLen+2*f.Params.SecLevel+1, mu)
	if err != nil {
		return nil, nil, err
	}

	BHat := make(data.Matrix, f.Params.VecLen+f.Params.SecLevel)
	BStarHat := make(data.Matrix, f.Params.VecLen+f.Params.SecLevel)
	for j := 0; j < f.Params.VecLen+f.Params.SecLevel; j++ {
		if j < f.Params.VecLen {
			BHat[j] = B[j]
			BStarHat[j] = BStar[j]
		} else if j < f.Params.SecLevel+f.Params.VecLen {
			BHat[j] = B[j+f.Params.VecLen]
			BStarHat[j] = BStar[j+f.Params.VecLen+f.Params.SecLevel]
		}
	}

	return &FHTAO20SecKey{BHat: BHat, BStarHat: BStarHat}, gTMu, nil
}

/*// randomOB is a helping function that samples a random l x l matrix B
// and calculates BStar = mu * (B^-1)^T
func randomOB(l int, mu *big.Int) (data.Matrix, data.Matrix, error) {
	sampler := sample.NewUniform(bn256.Order)
	B, err := data.NewRandomMatrix(l, l, sampler)
	if err != nil {
		return nil, nil, err
	}

	BStar, _, err := B.InverseModGauss(bn256.Order)
	if err != nil {
		return nil, nil, err
	}
	BStar = BStar.Transpose()
	BStar = BStar.MulScalar(mu)
	BStar = BStar.Mod(bn256.Order)

	return B, BStar, nil
}
*/

// DeriveKey takes a vector y and
// master secret key, and returns the functional encryption key. That is
// a key that for an encrypted x allows to calculate the
// inner products <x,y>. In case the key could not
// be derived, it returns an error.
func (f FHTAO20) DeriveKey(y data.Vector, secKey data.Matrix) (data.VectorG2, error) {
	sampler := sample.NewUniform(bn256.Order)
	gamma, err := data.NewRandomVector(f.Params.SecLevel, sampler)
	if err != nil {
		return nil, err
	}

	keyVec := data.NewConstantVector(2*f.Params.VecLen+2*f.Params.SecLevel+1, big.NewInt(0))
	var s *big.Int
	for j := 0; j < f.Params.VecLen+f.Params.SecLevel; j++ {
		if j < f.Params.VecLen {
			s = y[j]
		} else {
			s = gamma[j-f.Params.VecLen]
		}

		keyVec = keyVec.Add(secKey[j].MulScalar(s))
		keyVec = keyVec.Mod(bn256.Order)
	}

	return keyVec.MulG2(), nil
}

// Encrypt encrypts input vector x with the master secret key.
// It returns a ciphertext vector. If encryption failed, error is returned.
func (f FHTAO20) Encrypt(x data.Vector, secKey data.Matrix) (data.VectorG1, error) {
	sampler := sample.NewUniform(bn256.Order)
	phi, err := data.NewRandomVector(f.Params.SecLevel, sampler)
	if err != nil {
		return nil, err
	}

	keyVec := data.NewConstantVector(2*f.Params.VecLen+2*f.Params.SecLevel+1, big.NewInt(0))
	var s *big.Int
	for j := 0; j < f.Params.VecLen+f.Params.SecLevel; j++ {
		if j < f.Params.VecLen {
			s = x[j]

		} else {
			s = phi[j-f.Params.VecLen]

		}

		keyVec = keyVec.Add(secKey[j].MulScalar(s))
		keyVec = keyVec.Mod(bn256.Order)
	}

	return keyVec.MulG1(), nil
}

// Decrypt accepts the ciphertext as a encryption of vector x
// and a functional encryption key corresponding to a vector y.
// It returns the  inner product <x,y>. If decryption
// failed, an error is returned.
func (f *FHTAO20) Decrypt(cipher data.VectorG1, key data.VectorG2, pubKey *bn256.GT) (*big.Int, error) {
	sum := new(bn256.GT).ScalarBaseMult(big.NewInt(0))

	for j := 0; j < 2*f.Params.VecLen+2*f.Params.SecLevel+1; j++ {
		paired := bn256.Pair(cipher[j], key[j])
		sum.Add(paired, sum)
	}

	boundXY := new(big.Int).Mul(f.Params.BoundX, f.Params.BoundY)
	bound := new(big.Int).Mul(big.NewInt(int64(f.Params.VecLen)), boundXY)

	dec, err := dlog.NewCalc().InBN256().WithNeg().WithBound(bound).BabyStepGiantStep(sum, pubKey)

	return dec, err
}

// DecryptWOSearch accepts the ciphertext as a encryption of vector x
// and a functional encryption key corresponding to a vector y.
// It returns the inner product g_t^<x,y>.
func (f *FHTAO20) DecryptWOSearch(cipher data.VectorG1, key data.VectorG2, pubKey *bn256.GT) *bn256.GT {
	sum := new(bn256.GT).ScalarBaseMult(big.NewInt(0))

	for j := 0; j < 2*f.Params.VecLen+2*f.Params.SecLevel+1; j++ {
		paired := bn256.Pair(cipher[j], key[j])
		sum.Add(paired, sum)
	}

	return sum
}
