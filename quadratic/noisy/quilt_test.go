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
	"time"

	"github.com/JasZal/gofe/data"
	"github.com/JasZal/gofe/quadratic/noisy"
	"github.com/JasZal/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestSM_NMCFE(t *testing.T) {

	// choose the parameters for the scheme
	secLevel := 1
	boundX := big.NewInt(128)
	boundY := big.NewInt(128)
	boundN := big.NewInt(10)
	vecLen := 1
	numClient := 10
	label := make([]byte, 16)
	//nrWorkers := 10

	fmt.Printf("***********NMCFE: clients: %d, veclen: %d*************\n", numClient, vecLen)

	// build the scheme
	start := time.Now()
	fe := noisy.NewOTNMCFE(secLevel, numClient, vecLen, boundX, boundY, boundN)
	fmt.Println("time Setup: ", time.Since(start))

	// generate master secret key, encryption keys and public key
	start = time.Now()
	masterSecKey, enckeys, pubKey, err := fe.GenerateKeys()
	fmt.Println("time Generate Keys: ", time.Since(start))
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

	//fmt.Println("x:", x)

	// encrypt vectors
	start = time.Now()
	cipher := make([]*noisy.OTNMCFECT, numClient)
	for i := 0; i < numClient; i++ {
		cipher[i], err = fe.Encrypt(enckeys[i], x[i], label)
		if err != nil {
			t.Fatalf("Error during encryption: %v", err)
		}
	}
	fmt.Println("time Encryption total: ", time.Since(start))

	// sample inner product vectors and put them in a matrix
	sampler = sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(boundY), big.NewInt(1)), boundY)
	yQuad := make([][]data.Matrix, numClient)
	yLin, err := data.NewRandomMatrix(numClient, vecLen, sampler)

	if err != nil {
		t.Fatalf("Error during function sampling: %v", err)
	}
	yCon, err := sampler.Sample()
	if err != nil {
		t.Fatalf("Error during function sampling: %v", err)
	}
	for i := 0; i < numClient; i++ {
		yQuad[i] = make([]data.Matrix, vecLen)
		for j := 0; j < vecLen; j++ {
			yQuad[i][j] = data.NewConstantMatrix(numClient, vecLen, big.NewInt(0))
			for k := 0; k < numClient; k++ {
				for l := 0; l < vecLen; l++ {
					if i < k || (i == k && j <= l) {
						yQuad[i][j][k][l], _ = sampler.Sample()

					} else {
						yQuad[i][j][k][l] = big.NewInt(0)
					}

				}

				if err != nil {
					t.Fatalf("Error during function sampling: %v", err)
				}

			}
		}
	}

	// fmt.Printf("yQuad: %v\n", yQuad)
	// fmt.Printf("yLin: %v\n", yLin)
	// fmt.Printf("yCon: %v\n", yCon)
	sampler = sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(boundN), big.NewInt(1)), boundN)
	noise, _ := sampler.Sample()

	// derive a functional key for matrix y
	start = time.Now()
	key, err := fe.DeriveKey(yQuad, yLin, yCon, noise, label, masterSecKey)

	if err != nil {
		fmt.Printf("Error during derive key: %v", err)
	}
	fmt.Println("time Derive Keys: ", time.Since(start))

	// decryptor decrypts the quadratic function without knowing
	// vectors x and c
	// check the correctness of the result

	sumCheck := new(big.Int).Set(yCon)
	for i := 0; i < numClient; i++ {
		for j := 0; j < vecLen; j++ {
			sumCheck.Add(sumCheck, new(big.Int).Mul(yLin[i][j], x[i][j]))
			for k := 0; k < numClient; k++ {
				for l := 0; l < vecLen; l++ {
					sumCheck.Add(sumCheck, new(big.Int).Mul(yQuad[i][j][k][l], new(big.Int).Mul(x[i][j], x[k][l])))
				}
			}
		}
	}
	//todo add noise
	sumCheck.Add(sumCheck, noise)
	//todo change
	start = time.Now()
	sum, err := fe.Decrypt(key, yQuad, cipher, pubKey)
	// fe.DecryptWOSearch(key, yQuad, cipher, pubKey)
	if err != nil {
		fmt.Printf("Error during decryption: %v\n", err)
		t.Error()
	}

	fmt.Println("time Decryption total:", time.Since(start))
	// fmt.Printf("sumCheck: %v\n", sumCheck)
	// fmt.Printf("sum: %v\n", sum)

	assert.Equal(t, sum.Cmp(sumCheck), 0, "obtained incorrect sum")

}
