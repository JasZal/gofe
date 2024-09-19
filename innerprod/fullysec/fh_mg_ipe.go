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

// FHMGIPEParams represents configuration parameters for the FHMGIPE
// scheme instance.
// SecLevel (int): The parameter defines the security assumption of the scheme, k >= 2, MMDH_k assumption
// NumClients (int): The number of clients participating
// VecLenX1 (int): The length of vectors x_1 that clients encrypt.
// VecLenX2 (int): The length of vectors x_2 that clients encrypt.
// BoundX1 (int): The value by which the coordinates of encrypted vectors x_1 are bounded.
// BoundY1 (int): The value by which the coordinates of inner product vectors y_1 are bounded.
// BoundX2 (int): The value by which the coordinates of encrypted vectors x_2 are bounded.
// BoundY2 (int): The value by which the coordinates of inner product vectors y_2 are bounded.
type FHMGIPEParams struct {
	SecLevel   int
	NumClients int
	VecLenX1   int
	VecLenX2   int
	BoundX1    *big.Int
	BoundY1    *big.Int
	BoundX2    *big.Int
	BoundY2    *big.Int
}

// FHMGIPE represents a Function Hiding Mixed-Group Inner Product
// Encryption scheme based on the paper by S. Agrawal, R. Goyal, J. Tomida
// "Multi-Input Quadratic Functional Encryption from Pairings".
// It allows clients to encrypt vectors {(x_1,1, x_2,1),...,x_1,m, x_2,m)} and derive a secret key
// based on an inner product vectors {(y_1,1, y_2,1),...,y_1,m, y_2,m)} so that a decryptor can
// decrypt the sum of inner products <x_1,1,y_1,1> + <x_2,1,y_2,1> ... + <x_1,m, y_1,m> + <x_2,m,y_2,m> without
// revealing vectors x_i,j or y_i,j.
// The scheme is based on an iFE scheme (TAO20: "Efficient Inner Product Functional Encryption with Full-Hiding Security")
// and a miFE scheme (DOT18: Full-Hiding (Unbounded) Multi-Input Inner Product Functional Encryption from the k-Linear Assumption)

// This struct contains the shared choice for parameters on which the
// functionality of the scheme depend.
type FHMGIPE struct {
	Params *FHMGIPEParams
}

// FHMGIPESecKey represents a master secret key in FHMGIPE scheme.
type FHMGIPESecKey struct {
	MiMSK *FHMultiIPESecKey
	IMSK  []*FHTAO20SecKey
}

// FHMGIPESecKey represents a master secret key in FHMGIPE scheme.
type FHMGIPEEncKey struct {
	MiSK data.Matrix
	ISK  data.Matrix
}

// FHMGIPECT represents a ciphertext in FHMGIPE scheme.
type FHMGIPECT struct {
	MiCT data.VectorG1
	IDK  data.VectorG2
}

// FHMGIPEDK represents a decryption key in FHMGIPE scheme.
type FHMGIPEDK struct {
	MiDK data.MatrixG2
	ICT  data.MatrixG1
}

// NewFHMGIPE configures a new instance of the scheme. See struct
// FHMGIPEParams for the description of the parameters. It returns
// a new FHMGIPE instance.
func NewFHMGIPE(secLevel, numClients, vecLenx1, vecLenx2 int, boundx1, boundy1, boundx2, boundy2 *big.Int) *FHMGIPE {
	params := &FHMGIPEParams{SecLevel: secLevel, NumClients: numClients,
		VecLenX1: vecLenx1, VecLenX2: vecLenx2, BoundX1: boundx1, BoundY1: boundy1, BoundX2: boundx2, BoundY2: boundy2}
	return &FHMGIPE{Params: params}
}

// NewFHMGIPEFromParams takes configuration parameters of an existing
// FHMGIPE scheme instance, and reconstructs the scheme with the same
// configuration parameters. It returns a new FHMGIPE instance.
func NewFHMGIPEFromParams(params *FHMGIPEParams) *FHMGIPE {
	return &FHMGIPE{
		Params: params,
	}
}

// GenerateKeys generates a pair of master secret key and public key
// for the scheme. It returns an error in case keys could not be
// generated.
func (f FHMGIPE) GenerateKeys() (*FHMGIPESecKey, []*FHMGIPEEncKey, *bn256.GT, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), bn256.Order)
	mu, err := sampler.Sample()

	if err != nil {
		return nil, nil, nil, err
	}

	return f.GenerateKeysWOS(mu)
}

// GenerateKeys generates a pair of master secret key and public key
// for the scheme. It returns an error in case keys could not be
// generated.
func (f FHMGIPE) GenerateKeysWOS(mu *big.Int) (*FHMGIPESecKey, []*FHMGIPEEncKey, *bn256.GT, error) {

	miFE := NewFHMultiIPE(f.Params.SecLevel, f.Params.NumClients, f.Params.VecLenX1+f.Params.VecLenX2+f.Params.SecLevel+1, f.Params.BoundX1, f.Params.BoundY1)
	miMSK, pp, err := miFE.GenerateKeysWOS(mu)
	if err != nil {
		return nil, nil, nil, err
	}

	iMSK := make([]*FHTAO20SecKey, f.Params.NumClients)
	enckey := make([]*FHMGIPEEncKey, f.Params.NumClients)

	for i := 0; i < f.Params.NumClients; i++ {
		iFE := NewFHTAO20(f.Params.SecLevel, f.Params.VecLenX2+f.Params.SecLevel+1, f.Params.BoundX2, f.Params.BoundY2)
		iMSK[i], _, err = iFE.GenerateKeysWOS(mu)
		if err != nil {
			return nil, nil, nil, err
		}

		//make encryption keys
		enckey[i] = &FHMGIPEEncKey{MiSK: miMSK.BHat[i], ISK: iMSK[i].BStarHat}

	}

	return &FHMGIPESecKey{MiMSK: miMSK, IMSK: iMSK}, enckey, pp, nil
}

// DeriveKey takes a matrix y whose rows are input vector (y_1,1, y_2,1),...,(y_1,m, y_2,m) and
// master secret key, and returns the functional encryption key. That is
// a key that for encrypted (x_1,1, x_2,1),...,(x_1,m, x_2,m) allows to calculate the sum of
// inner products <x_1,1,y_1,1> + <x_2,1,y_2,1> ... + <x_1,m, y_1,m> + <x_2,m,y_2,m>. In case the key could not
// be derived, it returns an error.
func (f FHMGIPE) DeriveKey(y1 data.Matrix, y2 data.Matrix, msk *FHMGIPESecKey) (*FHMGIPEDK, error) {

	sampler := sample.NewUniform(bn256.Order)
	a, err := data.NewRandomVector(f.Params.SecLevel, sampler)
	if err != nil {
		return nil, err
	}

	if len(y1[0]) > f.Params.VecLenX1 {
		return nil, err
	}
	ytilde := data.NewConstantMatrix(f.Params.NumClients, f.Params.VecLenX1+f.Params.VecLenX2+f.Params.SecLevel+1, big.NewInt(0))
	for i := 0; i < f.Params.NumClients; i++ {
		for j := 0; j < f.Params.VecLenX1+f.Params.SecLevel; j++ {
			if j < f.Params.VecLenX1 {
				ytilde[i][j] = y1[i][j]
			} else {
				ytilde[i][j+f.Params.VecLenX2] = a[j-f.Params.VecLenX1]
			}
		}
	}

	params1 := &FHMultiIPEParams{SecLevel: f.Params.SecLevel, NumClients: f.Params.NumClients, VecLen: f.Params.VecLenX1 + f.Params.VecLenX2 + f.Params.SecLevel + 1,
		BoundX: f.Params.BoundX1, BoundY: f.Params.BoundY1}
	midk, err := NewFHMultiIPEFromParams(params1).DeriveKey(ytilde, msk.MiMSK)
	if err != nil {
		return nil, err
	}

	ict := make(data.MatrixG1, f.Params.NumClients)
	params2 := &FHTAO20Params{SecLevel: f.Params.SecLevel, VecLen: f.Params.VecLenX2 + f.Params.SecLevel + 1,
		BoundX: f.Params.BoundX2, BoundY: f.Params.BoundY2}
	ife := NewFHTAO20FromParams(params2)
	for i := 0; i < f.Params.NumClients; i++ {
		if len(y2[i]) > f.Params.VecLenX2 {
			return nil, err
		}
		y2tilde := data.NewConstantVector(f.Params.VecLenX2+f.Params.SecLevel+1, big.NewInt(0))
		for j := 0; j < f.Params.VecLenX2+f.Params.SecLevel; j++ {
			if j < f.Params.VecLenX2 {
				y2tilde[j] = y2[i][j]
			} else {
				y2tilde[j] = a[j-f.Params.VecLenX2]
			}
		}
		ict[i], err = ife.Encrypt(y2tilde, msk.IMSK[i].BHat)
		if err != nil {
			return nil, err
		}

	}

	return &FHMGIPEDK{MiDK: midk, ICT: ict}, nil
}

// Encrypt encrypts input vector (x_1, x_2) with the provided part of the master secret key.
// It returns a ciphertext vector pair (miCT, iCT). If encryption failed, error is returned.
func (f FHMGIPE) Encrypt(x1, x2 data.Vector, i int, sk *FHMGIPEEncKey) (*FHMGIPECT, error) {
	sampler := sample.NewUniform(bn256.Order)
	z, err := data.NewRandomVector(f.Params.SecLevel, sampler)
	if err != nil {
		return nil, err
	}

	if len(x1) > f.Params.VecLenX1 {
		return nil, err
	}
	x1tilde := data.NewConstantVector(f.Params.VecLenX1+f.Params.VecLenX2+f.Params.SecLevel+1, big.NewInt(0))

	for j := 0; j < f.Params.VecLenX1+f.Params.SecLevel; j++ {
		if j < f.Params.VecLenX1 {
			x1tilde[j] = x1[j]
		} else {
			x1tilde[j+f.Params.VecLenX2] = z[j-f.Params.VecLenX1]
		}
	}

	params1 := &FHMultiIPEParams{SecLevel: f.Params.SecLevel, NumClients: f.Params.NumClients, VecLen: f.Params.VecLenX1 + f.Params.VecLenX2 + f.Params.SecLevel + 1,
		BoundX: f.Params.BoundX1, BoundY: f.Params.BoundY1}
	mict, err := NewFHMultiIPEFromParams(params1).Encrypt(x1tilde, sk.MiSK)
	if err != nil {
		return nil, err
	}

	if len(x2) > f.Params.VecLenX2 {
		return nil, err
	}
	x2tilde := data.NewConstantVector(f.Params.VecLenX2+f.Params.SecLevel+1, big.NewInt(0))
	for j := 0; j < f.Params.VecLenX2+f.Params.SecLevel; j++ {
		if j < f.Params.VecLenX2 {
			x2tilde[j] = x2[j]
		} else {
			x2tilde[j] = new(big.Int).Neg(z[j-f.Params.VecLenX2])
		}
	}

	params2 := &FHTAO20Params{SecLevel: f.Params.SecLevel, VecLen: f.Params.VecLenX2 + f.Params.SecLevel + 1,
		BoundX: f.Params.BoundX2, BoundY: f.Params.BoundY2}

	idk, err := NewFHTAO20FromParams(params2).DeriveKey(x2tilde, sk.ISK)
	if err != nil {
		return nil, err
	}
	return &FHMGIPECT{MiCT: mict, IDK: idk}, nil
}

// Decrypt accepts the ciphertext as a matrix whose rows are encryptions of vectors
// x_1,...,x_m and a functional encryption key corresponding to vectors y_1,...,y_m.
// It returns the sum of inner products <x_1,y_1> + ... + <x_m, y_m>. If decryption
// failed, an error is returned.
func (f *FHMGIPE) DecryptWOS(cipher []*FHMGIPECT, dk *FHMGIPEDK, pubKey *bn256.GT) *bn256.GT {
	sum := new(bn256.GT).ScalarBaseMult(big.NewInt(0))

	params1 := &FHMultiIPEParams{SecLevel: f.Params.SecLevel, NumClients: f.Params.NumClients, VecLen: f.Params.VecLenX1 + f.Params.VecLenX2 + f.Params.SecLevel + 1,
		BoundX: f.Params.BoundX1, BoundY: f.Params.BoundY1}
	micipher := make(data.MatrixG1, f.Params.NumClients)
	for i := 0; i < f.Params.NumClients; i++ {
		micipher[i] = cipher[i].MiCT
	}
	sum.Add(NewFHMultiIPEFromParams(params1).DecryptWOSearch(micipher, dk.MiDK, pubKey), sum)

	params2 := &FHTAO20Params{SecLevel: f.Params.SecLevel, VecLen: f.Params.VecLenX2 + f.Params.SecLevel + 1,
		BoundX: f.Params.BoundX2, BoundY: f.Params.BoundY2}
	ife := NewFHTAO20FromParams(params2)
	for i := 0; i < f.Params.NumClients; i++ {
		sum.Add(ife.DecryptWOSearch(dk.ICT[i], cipher[i].IDK, pubKey), sum)
	}

	return sum
}

// Decrypt accepts the ciphertext as a matrix whose rows are encryptions of vectors
// x_1,...,x_m and a functional encryption key corresponding to vectors y_1,...,y_m.
// It returns the sum of inner products <x_1,y_1> + ... + <x_m, y_m>. If decryption
// failed, an error is returned.
func (f *FHMGIPE) Decrypt(cipher []*FHMGIPECT, dk *FHMGIPEDK, pubKey *bn256.GT) (*big.Int, error) {
	sum := f.DecryptWOS(cipher, dk, pubKey)

	boundXY1 := new(big.Int).Mul(f.Params.BoundX1, f.Params.BoundY1)
	boundXY2 := new(big.Int).Mul(f.Params.BoundX2, f.Params.BoundY2)
	bound1 := new(big.Int).Mul(big.NewInt(int64(f.Params.NumClients*f.Params.VecLenX1)), boundXY1)
	bound2 := new(big.Int).Mul(big.NewInt(int64(f.Params.NumClients*f.Params.VecLenX1)), boundXY2)

	dec, err := dlog.NewCalc().InBN256().WithNeg().WithBound(new(big.Int).Add(bound1, bound2)).BabyStepGiantStep(sum, pubKey)

	return dec, err
}
