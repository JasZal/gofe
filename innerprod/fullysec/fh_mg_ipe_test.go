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

package fullysec_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/JasZal/gofe/data"
	"github.com/JasZal/gofe/innerprod/fullysec"
	"github.com/JasZal/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestFH_Mg_IPE(t *testing.T) {
	// choose the parameters for the scheme
	secLevel := 2
	vecLenm1 := 2
	vecLenm2 := 2
	numClient := 1
	bound := big.NewInt(128)

	// build the scheme
	fhmg := fullysec.NewFHMGIPE(secLevel, numClient, vecLenm1, vecLenm2, bound, bound, bound, bound)

	// generate master secret key and public key
	masterSecKey, enckeys, pubKey, err := fhmg.GenerateKeys()
	if err != nil {
		t.Fatalf("Error during keys generation: %v", err)
	}

	// sample vectors that will be encrypted
	sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(bound), big.NewInt(1)), bound)

	x1 := make(data.Matrix, numClient)
	x2 := make(data.Matrix, numClient)
	//x[0] = Message{x1: data.NewConstantVector(vecLen, big.NewInt(1)), x2: data.NewConstantVector(vecLen, big.NewInt(2))}

	for i := 0; i < numClient; i++ {
		x1[i], err = data.NewRandomVector(vecLenm1, sampler)
		if err != nil {
			t.Fatalf("Error during random vector generation: %v", err)
		}
		x2[i], err = data.NewRandomVector(vecLenm2, sampler)

		if err != nil {
			t.Fatalf("Error during random vector generation: %v", err)
		}
	}

	//encrypt vectors
	cipher := make([]*fullysec.FHMGIPECT, numClient)
	for i := 0; i < numClient; i++ {
		cipher[i], err = fhmg.Encrypt(x1[i], x2[i], i, enckeys[i])
		if err != nil {
			t.Fatalf("Error during encryption: %v", err)
		}
	}

	// sample inner product vectors and put them in a matrix
	y1 := make(data.Matrix, numClient)
	y2 := make(data.Matrix, numClient)
	for i := 0; i < numClient; i++ {
		y1[i], err = data.NewRandomVector(vecLenm1, sampler)
		if err != nil {
			t.Fatalf("Error during random vector generation: %v", err)
		}
		y2[i], err = data.NewRandomVector(vecLenm2, sampler)
		if err != nil {
			t.Fatalf("Error during random vector generation: %v", err)
		}
	}

	// derive a functional key for vector y
	key, err := fhmg.DeriveKey(y1, y2, masterSecKey)

	if err != nil {
		t.Fatalf("Error during key derivation: %v", err)
	}

	// simulate a decryptor
	decryptor := fullysec.NewFHMGIPEFromParams(fhmg.Params)

	// decryptor decrypts the inner-product without knowing
	// vectors x and y
	xy, err := decryptor.Decrypt(cipher, key, pubKey)
	if err != nil {
		if err != nil {
			fmt.Printf("Error during decryption: %v", err)
		}
		t.Fatalf("Error during decryption: %v", err)
	}

	// check the correctness of the result
	xy1Check, err := x1.Dot(y1)

	if err != nil {
		t.Fatalf("Error during inner product calculation")
	}
	xy2Check, err := x2.Dot(y2)

	if err != nil {
		t.Fatalf("Error during inner product calculation")
	}
	xyCheck := big.NewInt(0).Add(xy1Check, xy2Check)

	assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")

}
