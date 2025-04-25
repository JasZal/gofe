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

func TestSMNH_Quad(t *testing.T) {
	// choose the parameters for the scheme
	secLevel := 1
	vecLen := 1
	numClient := 2
	boundX := big.NewInt(30)
	boundY := big.NewInt(30)
	boundN := big.NewInt(10)

	//fmt.Printf("***********OT noisy Quad: clients: %d, veclen: %d*************\n", numClient, vecLen)

	// build the scheme
	//start := time.Now()
	fe := noisy.NewSMNH(secLevel, numClient, vecLen, boundX, boundY, boundN)
	//fmt.Println("time Setup: ", time.Since(start))

	// generate master secret key, encryption keys and public key
	//start = time.Now()
	masterSecKey, enckeys, pubKey, err := fe.GenerateKeys()
	//fmt.Println("time Generate Keys: ", time.Since(start))
	if err != nil {
		t.Fatalf("Error during keys generation: %v", err)
	}

	// sample vectors that will be encrypted
	sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(boundX), big.NewInt(1)), boundX)
	x := make(data.Matrix, numClient)

	for i := 0; i < numClient; i++ {
		x[i], err = data.NewRandomVector(vecLen, sampler)

		if err != nil {
			t.Fatalf("Error during message sampling: %v", err)
		}

	}

	// encrypt vectors
	//start = time.Now()
	cipher := make([]*noisy.SMNHCT, numClient)
	for i := 0; i < numClient; i++ {
		cipher[i], err = fe.Encrypt(enckeys[i], x[i])
		if err != nil {
			t.Fatalf("Error during encryption: %v", err)
		}
	}
	//fmt.Println("time Encryption total: ", time.Since(start))

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
					if i < k || (i == k && j <= l) {
						c[i][j][k][l], _ = sampler.Sample()
						cN[i][j][k][l] = new(big.Int).Set(c[i][j][k][l])

					} else {
						c[i][j][k][l] = big.NewInt(0)
					}
				}

			}
		}
	}

	// sample noise
	sampler = sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(boundN), big.NewInt(1)), boundN)
	noise, _ := sampler.Sample()

	// derive a functional key for vector c
	//start = time.Now()
	key, err := fe.DeriveKey(c, noise, masterSecKey)
	//fmt.Println("time Derive Keys: ", time.Since(start))
	if err != nil {
		fmt.Printf("Error during derive key: %v", err)
	}

	// simulate a decryptor
	decryptor := noisy.NewSMNHFromParams(fe.Params)

	// decryptor decrypts the quadratic function without knowing
	// vectors x and c

	sum, err := decryptor.Decrypt(cipher, key, big.NewInt(0), pubKey)
	//start = time.Now()
	decryptor.DecryptWOSearch(cipher, key, pubKey)
	//fmt.Println("time Decryption WO disc. Logarithm search: ", time.Since(start))

	if err != nil {

		t.Fatalf("Error during decryption: %v", err)
	}

	// check the correctness of the result
	sumCheck := big.NewInt(0)

	for i := 0; i < numClient; i++ {
		for j := 0; j < vecLen; j++ {
			for k := 0; k < numClient; k++ {
				for l := 0; l < vecLen; l++ {
					sumCheck.Add(sumCheck, new(big.Int).Mul(cN[i][j][k][l], new(big.Int).Mul(x[i][j], x[k][l])))
				}
			}
		}
	}
	sumCheck.Add(sumCheck, noise)

	assert.Equal(t, sum.Cmp(sumCheck), 0, "obtained incorrect sum")

}
