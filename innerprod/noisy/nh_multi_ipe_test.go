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
	"github.com/JasZal/gofe/innerprod/noisy"
	"github.com/JasZal/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestOTNHMulti(t *testing.T) {
	// choose the parameters for the scheme

	vecLen := 2
	numClient := 2
	secLevel := 2
	boundX := big.NewInt(128)
	boundN := big.NewInt(128)

	// build the scheme
	fe := noisy.NewOTNHMultiIPE(secLevel, numClient, vecLen, boundX, boundX)

	// generate master secret key
	masterSecKey, pk, err := fe.GenerateKeys()
	if err != nil {
		t.Fatalf("Error during key generation: %v", err)
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
	cipher := make([]data.VectorG1, numClient)
	for i := 0; i < numClient; i++ {
		cipher[i], err = fe.Encrypt(x[i], masterSecKey.BHat[i])
		if err != nil {
			t.Fatalf("Error during encryption: %v", err)
		}
	}

	// sample function vectors

	y := make(data.Matrix, numClient)

	for i := 0; i < numClient; i++ {
		y[i], err = data.NewRandomVector(vecLen, sampler)

		if err != nil {
			t.Fatalf("Error during message sampling: %v", err)
		}

	}

	// sample noise
	sampler = sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(boundN), big.NewInt(1)), boundN)
	noise, _ := sampler.Sample()

	// derive a functional key for matrix y
	key, err := fe.DeriveKey(y, masterSecKey, noise.Int64())
	if err != nil {
		fmt.Printf("Error during derive key: %v", err)
	}

	// simulate a decryptor
	decryptor := noisy.NewOTNHMultiIPEFromParams(fe.Params)

	// decryptor decrypts the quadratic function without knowing
	// vectors x and c

	sum, err := decryptor.Decrypt(cipher, key, pk)

	if err != nil {

		t.Fatalf("Error during decryption: %v", err)
	}

	// check the correctness of the result
	sumCheck := big.NewInt(0)

	for i := 0; i < numClient; i++ {
		interm, err := x[i].Dot(y[i])
		if err != nil {

			t.Fatalf("Error during decryption: %v", err)
		}

		sumCheck.Add(sumCheck, interm)
	}
	sumCheck.Add(sumCheck, noise)

	assert.Equal(t, sum.Cmp(sumCheck), 0, "obtained incorrect sum")

}
