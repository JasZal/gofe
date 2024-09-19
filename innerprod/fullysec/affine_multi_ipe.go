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

/*
NOTE: This file is copied from the original gofe library and edited to obtain a new noisy FE scheme!
*/

package fullysec

import (
	"fmt"
	"math/big"

	"github.com/JasZal/gofe/data"
	"github.com/JasZal/gofe/internal/dlog"
	"github.com/JasZal/gofe/sample"
	"github.com/fentec-project/bn256"
)

// AffineMultiIPEParams represents configuration parameters for the AffineMultiIPE
// scheme instance.
// SecLevel (int): The parameter defines the security assumption of the scheme,
// so called k-Lin assumption, where k is the specified SecLevel.
// NumClients (int): The number of clients participating
// VecLen (int): The length of vectors that clients encrypt.
// BoundX (int): The value by which the coordinates of encrypted vectors are bounded.
// BoundY (int): The value by which the coordinates of inner product vectors are bounded.
type AffineMultiIPEParams struct {
	SecLevel   int
	NumClients int
	VecLen     int
	BoundX     *big.Int
	BoundY     *big.Int
}

type MyKeyStruct struct {
	TheSecKey *AffineMultiIPESecKey
}

// AffineMultiIPE represents a Function Hiding Multi-input Inner Product
// Encryption scheme based on the paper by P. Datta, T. Okamoto, and
// J. Tomida:
// "Full-Hiding (Unbounded) Multi-Input Inner Product Functional Encryption
// from the 𝒌-Linear Assumption".
// It allows clients to encrypt vectors {x_1,...,x_m} and derive a secret key
// based on an inner product vectors {y_1,...,y_m, y_m+1} so that a decryptor can
// decrypt the sum of inner products <x_1,y_1> + ... + <x_m, y_m> + y_m+1 without
// revealing vectors x_i or y_i. The scheme is slightly modified from the
// original one to achieve a better performance. The difference is in
// storing the secret master key as matrices B, BStar, instead of matrices
// of elliptic curve elements g_1^B, g_2^BStar. This replaces elliptic curves
// operations with matrix multiplication.
//
// This struct contains the shared choice for parameters on which the
// functionality of the scheme depend.
type AffineMultiIPE struct {
	Params *AffineMultiIPEParams
}

// AffineMultiIPESecKey represents a master secret key in AffineMultiIPE scheme.
type AffineMultiIPESecKey struct {
	BHat     []data.Matrix
	BStarHat []data.Matrix
}

// NewAffineMultiIPE configures a new instance of the scheme. See struct
// AffineMultiIPEParams for the description of the parameters. It returns
// a new AffineMultiIPE instance.
func NewAffineMultiIPE(secLevel, numClients, vecLen int, boundX, boundY *big.Int) *AffineMultiIPE {
	params := &AffineMultiIPEParams{SecLevel: secLevel, NumClients: numClients,
		VecLen: vecLen, BoundX: boundX, BoundY: boundY}
	return &AffineMultiIPE{Params: params}
}

// NewAffineMultiIPEFromParams takes configuration parameters of an existing
// AffineMultiIPE scheme instance, and reconstructs the scheme with the same
// configuration parameters. It returns a new AffineMultiIPE instance.
func NewAffineMultiIPEFromParams(params *AffineMultiIPEParams) *AffineMultiIPE {
	return &AffineMultiIPE{
		Params: params,
	}
}

// GenerateKeys generates a pair of master secret key and public key
// for the scheme. It returns an error in case keys could not be
// generated.
func (f AffineMultiIPE) GenerateKeys() (*AffineMultiIPESecKey, *bn256.GT, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), bn256.Order)
	mu, err := sampler.Sample()

	if err != nil {
		return nil, nil, err
	}
	gTMu := new(bn256.GT).ScalarBaseMult(mu)

	B := make([]data.Matrix, f.Params.NumClients)
	BStar := make([]data.Matrix, f.Params.NumClients)
	for i := 0; i < f.Params.NumClients; i++ {
		B[i], BStar[i], err = randomOB2(2*f.Params.VecLen+2*f.Params.SecLevel+1, mu)
		if err != nil {
			return nil, nil, err
		}
	}

	BHat := make([]data.Matrix, f.Params.NumClients)
	BStarHat := make([]data.Matrix, f.Params.NumClients)
	for i := 0; i < f.Params.NumClients; i++ {
		BHat[i] = make(data.Matrix, f.Params.VecLen+f.Params.SecLevel+1)
		BStarHat[i] = make(data.Matrix, f.Params.VecLen+f.Params.SecLevel)
		for j := 0; j < f.Params.VecLen+f.Params.SecLevel+1; j++ {
			if j < f.Params.VecLen {
				BHat[i][j] = B[i][j]
				BStarHat[i][j] = BStar[i][j]
			} else if j == f.Params.VecLen {
				BHat[i][j] = B[i][j+f.Params.VecLen]
				BStarHat[i][j] = BStar[i][j+f.Params.VecLen]
			} else if j < f.Params.VecLen+f.Params.SecLevel {
				BHat[i][j] = B[i][j-1+f.Params.VecLen+f.Params.SecLevel]
				BStarHat[i][j] = BStar[i][j+f.Params.VecLen]
			} else {
				BHat[i][j] = B[i][j-1+f.Params.VecLen+f.Params.SecLevel]
			}
		}
	}

	return &AffineMultiIPESecKey{BHat: BHat, BStarHat: BStarHat}, gTMu, nil
}

// GenerateKeys generates a pair of master secret key and public key
// for the scheme. It returns an error in case keys could not be
// generated.
func (f AffineMultiIPE) GenerateKeysWOS(mu *big.Int) (*AffineMultiIPESecKey, *bn256.GT, error) {

	gTMu := new(bn256.GT).ScalarBaseMult(mu)
	var err error
	B := make([]data.Matrix, f.Params.NumClients)
	BStar := make([]data.Matrix, f.Params.NumClients)
	for i := 0; i < f.Params.NumClients; i++ {
		B[i], BStar[i], err = randomOB2(2*f.Params.VecLen+2*f.Params.SecLevel+1, mu)
		if err != nil {
			return nil, nil, err
		}
	}

	BHat := make([]data.Matrix, f.Params.NumClients)
	BStarHat := make([]data.Matrix, f.Params.NumClients)
	for i := 0; i < f.Params.NumClients; i++ {
		BHat[i] = make(data.Matrix, f.Params.VecLen+f.Params.SecLevel+1)
		BStarHat[i] = make(data.Matrix, f.Params.VecLen+f.Params.SecLevel)
		for j := 0; j < f.Params.VecLen+f.Params.SecLevel+1; j++ {
			if j < f.Params.VecLen {
				BHat[i][j] = B[i][j]
				BStarHat[i][j] = BStar[i][j]
			} else if j == f.Params.VecLen {
				BHat[i][j] = B[i][j+f.Params.VecLen]
				BStarHat[i][j] = BStar[i][j+f.Params.VecLen]
			} else if j < f.Params.VecLen+f.Params.SecLevel {
				BHat[i][j] = B[i][j-1+f.Params.VecLen+f.Params.SecLevel]
				BStarHat[i][j] = BStar[i][j+f.Params.VecLen]
			} else {
				BHat[i][j] = B[i][j-1+f.Params.VecLen+f.Params.SecLevel]
			}
		}
	}

	return &AffineMultiIPESecKey{BHat: BHat, BStarHat: BStarHat}, gTMu, nil
}

// randomOB2 is a helping function that samples a random l x l matrix B
// and calculates BStar = mu * (B^-1)^T
func randomOB2(l int, mu *big.Int) (data.Matrix, data.Matrix, error) {
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

// DeriveKey takes a matrix y whose rows are input vector y_1,...,y_m and
// master secret key, and returns the functional encryption key. That is
// a key that for encrypted x_1,...,x_m allows to calculate the sum of
// inner products <x_1,y_1> + ... + <x_m, y_m>. In case the key could not
// be derived, it returns an error.
func (f AffineMultiIPE) DeriveKey(y data.Matrix, secKey *AffineMultiIPESecKey, c *big.Int) (data.MatrixG2, error) {

	sampler := sample.NewUniform(bn256.Order)
	gamma, err := data.NewRandomMatrix(f.Params.SecLevel, f.Params.NumClients, sampler)
	if err != nil {
		return nil, err
	}

	ones := data.NewConstantVector(f.Params.NumClients-1, big.NewInt(1))
	//random vector generatet from gamma
	r := data.NewVector(gamma[0][0:(f.Params.NumClients - 1)])
	//dotproduct of r and ones
	sum, err := r.Dot(ones)
	if err != nil {
		return nil, err
	}

	//compute modulus of sum, negate it add noise to it/////////////
	sum.Neg(sum).Mod(sum, bn256.Order)
	sum.Add(sum, c)
	gamma[0][f.Params.NumClients-1] = sum

	zeros := data.NewConstantVector(2*f.Params.VecLen+2*f.Params.SecLevel+1, big.NewInt(0))
	keyMat := make(data.Matrix, f.Params.NumClients)
	var s *big.Int
	for i := 0; i < f.Params.NumClients; i++ {
		keyMat[i] = zeros.Copy()
		for j := 0; j < f.Params.VecLen+f.Params.SecLevel; j++ {
			if j < f.Params.VecLen {
				s = y[i][j]
			} else {
				s = gamma[j-f.Params.VecLen][i]
			}

			keyMat[i] = keyMat[i].Add(secKey.BStarHat[i][j].MulScalar(s))
			keyMat[i] = keyMat[i].Mod(bn256.Order)
		}
	}

	return keyMat.MulG2(), nil
}

func (f AffineMultiIPE) DeriveKeyFake(a *int64) {
	fmt.Println(a)

}

// Encrypt encrypts input vector x with the provided part of the master secret key.
// It returns a ciphertext vector. If encryption failed, error is returned.
func (f AffineMultiIPE) Encrypt(x data.Vector, partSecKey data.Matrix) (data.VectorG1, error) {
	sampler := sample.NewUniform(bn256.Order)
	phi, err := data.NewRandomVector(f.Params.SecLevel, sampler)
	if err != nil {
		return nil, err
	}

	keyVec := data.NewConstantVector(2*f.Params.VecLen+2*f.Params.SecLevel+1, big.NewInt(0))
	var s *big.Int
	for j := 0; j < f.Params.VecLen+f.Params.SecLevel+1; j++ {
		if j < f.Params.VecLen {
			s = x[j]
		} else if j == f.Params.VecLen {
			s = big.NewInt(1)
		} else {
			s = phi[j-f.Params.VecLen-1]
		}

		keyVec = keyVec.Add(partSecKey[j].MulScalar(s))
		keyVec = keyVec.Mod(bn256.Order)
	}

	return keyVec.MulG1(), nil
}

// Decrypt accepts the ciphertext as a matrix whose rows are encryptions of vectors
// x_1,...,x_m and a functional encryption key corresponding to vectors y_1,...,y_m.
// It returns the sum of inner products <x_1,y_1> + ... + <x_m, y_m>. If decryption
// failed, an error is returned.
func (f *AffineMultiIPE) Decrypt(cipher data.MatrixG1, key data.MatrixG2, pubKey *bn256.GT) (*big.Int, error) {
	sum := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < f.Params.NumClients; i++ {
		for j := 0; j < 2*f.Params.VecLen+2*f.Params.SecLevel+1; j++ {
			paired := bn256.Pair(cipher[i][j], key[i][j])
			sum.Add(paired, sum)
		}
	}

	boundXY := new(big.Int).Mul(f.Params.BoundX, f.Params.BoundY)
	bound := new(big.Int).Mul(big.NewInt(int64(f.Params.NumClients*f.Params.VecLen)), boundXY)

	dec, err := dlog.NewCalc().InBN256().WithNeg().WithBound(bound).BabyStepGiantStep(sum, pubKey)

	return dec, err
}

// Decrypt accepts the ciphertext as a matrix whose rows are encryptions of vectors
// x_1,...,x_m and a functional encryption key corresponding to vectors y_1,...,y_m.
// It returns the sum of inner products <x_1,y_1> + ... + <x_m, y_m> in group representation.
func (f *AffineMultiIPE) DecryptWOSearch(cipher data.MatrixG1, key data.MatrixG2, pubKey *bn256.GT) *bn256.GT {
	sum := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < f.Params.NumClients; i++ {
		for j := 0; j < 2*f.Params.VecLen+2*f.Params.SecLevel+1; j++ {
			paired := bn256.Pair(cipher[i][j], key[i][j])
			sum.Add(paired, sum)
		}
	}

	return sum
}
