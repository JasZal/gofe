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

package noisy_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/JasZal/gofe/data"
	"github.com/JasZal/gofe/quadratic/noisy"
	"github.com/JasZal/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestNH_Quad(t *testing.T) {
	// choose the parameters for the scheme
	secLevel := 2
	xLen := 1
	numClient := 2
	boundX := big.NewInt(30)
	boundY := big.NewInt(30)
	boundN := big.NewInt(10)

	vecLen := xLen*xLen + xLen + 1

	// build the scheme
	fe := noisy.NewNHQuad(secLevel, numClient, vecLen, new(big.Int).Mul(boundX, boundX), boundY, boundN)

	// generate master secret key, encryption keys and public key

	masterSecKey, enckeys, pubKey, err := fe.GenerateKeys()
	if err != nil {
		t.Fatalf("Error during keys generation: %v", err)
	}

	// sample vectors that will be encrypted
	sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(boundX), big.NewInt(1)), boundX)
	x := make(data.Matrix, numClient)
	xK := make(data.Matrix, numClient)

	for i := 0; i < numClient; i++ {
		x[i], err = data.NewRandomVector(xLen, sampler)

		if err != nil {
			t.Fatalf("Error during message sampling: %v", err)
		}

		//compute Kroenecker product
		xK[i] = data.NewConstantVector(xLen*xLen+xLen+1, big.NewInt(1))
		for k := 0; k < xLen; k++ {
			for j := 0; j < xLen; j++ {
				xK[i][k*xLen+j] = new(big.Int).Mul(x[i][k], x[i][j])
			}
			xK[i][xLen*xLen+k] = x[i][k]
		}

	}

	// encrypt vectors

	cipher := make([]*noisy.NHQuadCT, numClient)
	for i := 0; i < numClient; i++ {
		cipher[i], err = fe.Encrypt(x[i], i, *enckeys[i])
		if err != nil {
			t.Fatalf("Error during encryption: %v", err)
		}
	}

	// sample inner product vectors and put them in a matrix
	c := make([][]data.Matrix, numClient)
	cN := make([][]data.Matrix, numClient)
	sampler = sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(boundY), big.NewInt(1)), boundY)
	for i := 0; i < numClient; i++ {
		c[i] = make([]data.Matrix, vecLen)
		cN[i] = make([]data.Matrix, vecLen)
		for j := 0; j < vecLen; j++ {
			c[i][j] = data.NewConstantMatrix(numClient, vecLen, big.NewInt(0))
			cN[i][j] = data.NewConstantMatrix(numClient, vecLen, big.NewInt(0))
			for k := 0; k < numClient; k++ {
				for l := 0; l < vecLen; l++ {
					if i < k {
						c[i][j][k][l], _ = sampler.Sample()
						cN[i][j][k][l] = new(big.Int).Set(c[i][j][k][l])
					} else {
						c[i][j][k] = data.NewConstantVector(vecLen, big.NewInt(0))
					}
				}

			}
		}
	}

	// sample noise
	sampler = sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(boundN), big.NewInt(1)), boundN)
	noise, _ := sampler.Sample()

	// derive a functional key for vector c

	key, err := fe.DeriveKey(c, noise, masterSecKey)
	if err != nil {
		fmt.Printf("Error during derive key: %v", err)
	}

	// simulate a decryptor
	decryptor := noisy.NewNHQuadFromParams(fe.Params)

	// decryptor decrypts the quadratic function without knowing
	// vectors x and c

	sum, err := decryptor.Decrypt(cipher, key, pubKey)

	if err != nil {

		t.Fatalf("Error during decryption: %v", err)
	}

	// check the correctness of the result
	sumCheck := big.NewInt(0)
	sumCheck.Add(sumCheck, noise)
	for i := 0; i < numClient; i++ {
		for j := 0; j < vecLen; j++ {
			for k := 0; k < numClient; k++ {
				for l := 0; l < vecLen; l++ {
					sumCheck.Add(sumCheck, new(big.Int).Mul(cN[i][j][k][l], new(big.Int).Mul(xK[i][j], xK[k][l])))
				}
			}
		}
	}

	assert.Equal(t, sum.Cmp(sumCheck), 0, "obtained incorrect sum")

}
