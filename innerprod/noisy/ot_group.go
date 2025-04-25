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

package noisy

import (
	"fmt"
	"math/big"

	"github.com/JasZal/gofe/data"
	"github.com/JasZal/gofe/sample"
)

// Todo
type OTParams struct {
	// number of encryptors
	NumClients int
	VecLen     int
	Bound      *big.Int
	BoundN     *big.Int
	ModulusL   *big.Int
}

// ToDo
type OT struct {
	Params *OTParams
}

// NewOT configures a new instance of the scheme.
// It accepts the number of slots (encryptors), the length of
// input vectors m, the bit length of the modulus (we are
// operating in the Z_p group), and a bound by which coordinates
// of input vectors are bounded.
//

func NewOT(numclients, veclen int, bound, boundN *big.Int) *OT {
	mod := new(big.Int).Add(new(big.Int).Mul(bound, new(big.Int).Mul(bound, big.NewInt((int64)(numclients)*(int64)(veclen)))), new(big.Int).Add(big.NewInt(1), boundN))

	params := &OTParams{NumClients: numclients,
		VecLen: veclen, ModulusL: mod, Bound: bound, BoundN: boundN}
	return &OT{Params: params}

}

// todo
func NewOTFromParams(params *OTParams) *OT {
	return &OT{
		Params: params,
	}
}

// OTSecKey is a secret key for OT multi input scheme.
type OTSecKey struct {
	Msk data.Matrix
}

// GenerateMasterKeys generates matrices comprised of master secret
// keys and encryption keys for the scheme.
//
// It returns an error in case  keys could not be generated.
func (sm *OT) GenerateKeys() (data.Matrix, error) {

	msk := make([]data.Vector, sm.Params.NumClients)
	var err error
	for i := 0; i < sm.Params.NumClients; i++ {
		msk[i], err = data.NewRandomVector(sm.Params.VecLen, sample.NewUniform(sm.Params.Bound))
		if err != nil {
			return nil, fmt.Errorf("error in random vector generation")
		}
	}

	return msk, nil
}

// Encrypt generates a ciphertext from the input vector x
// It returns the ciphertext vector.
// If encryption failed, error is returned.
func (sm *OT) Encrypt(x data.Vector, secKey data.Vector) (data.Vector, error) {
	if err := x.CheckBound(sm.Params.Bound); err != nil {
		return nil, err
	}

	ct := x.Add(secKey)
	ct = ct.Mod(sm.Params.ModulusL)

	return ct, nil
}

// DeriveKey takes master secret key and a matrix y comprised
// of input vectors, and returns the functional encryption key.
// In case the key could not be derived, it returns an error.
func (sm *OT) DeriveKey(msk data.Matrix, y data.Matrix, c *big.Int) (*big.Int, error) {
	if err := y.CheckBound(sm.Params.Bound); err != nil {
		return nil, err
	}
	z, err := msk.Dot(y)
	if err != nil {
		return nil, err
	}

	z.Add(z, new(big.Int).Mul(c, big.NewInt(-1)))
	z.Mod(z, sm.Params.ModulusL)

	return z, nil

}

// Decrypt accepts the matrix cipher comprised of encrypted vectors,
// functional encryption key, and a matrix y comprised of plaintext vectors.
// It returns the sum of inner products + constant.
// If decryption failed, error is returned.
func (sm *OT) Decrypt(cipher []data.Vector, deckey *big.Int, y data.Matrix) (*big.Int, error) {
	if err := y.CheckBound(sm.Params.Bound); err != nil {
		return nil, err
	}

	sum := big.NewInt(0)
	for i := 0; i < sm.Params.NumClients; i++ {
		interm, err := cipher[i].Dot(y[i])
		if err != nil {
			return nil, err
		}
		sum.Add(sum, interm)
	}

	res := new(big.Int).Sub(sum, deckey)
	res.Mod(res, sm.Params.ModulusL)
	return res, nil
}
