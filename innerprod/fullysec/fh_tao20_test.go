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
	"math/big"
	"testing"

	"github.com/JasZal/gofe/data"
	"github.com/JasZal/gofe/innerprod/fullysec"
	"github.com/JasZal/gofe/sample"
	"github.com/stretchr/testify/assert"
)



func TestFH_TAO20(t *testing.T) {
	// choose the parameters for the scheme
	secLevel := 2
	vecLen := 10
	bound := big.NewInt(128)

	// build the scheme
	fhtao := fullysec.NewFHTAO20(secLevel, vecLen, bound, bound)

	// generate master secret key and public key
	masterSecKey, pubKey, err := fhtao.GenerateKeys()
	if err != nil {
		t.Fatalf("Error during keys generation: %v", err)
	}
	

	// sample vectors that will be encrypted
	sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(bound), big.NewInt(1)), bound)

	x, err := data.NewRandomVector(vecLen, sampler)
	

	if err != nil {
		t.Fatalf("Error during random vector generation: %v", err)
	}

	// simulate  client and encrypt the vector
	client := fullysec.NewFHTAO20FromParams(fhtao.Params)
	cipher, err := client.Encrypt(x, masterSecKey.BHat)
	if err != nil {
		t.Fatalf("Error during encryption: %v", err)
	}

	// sample inner product vector
	y, err := data.NewRandomVector(vecLen, sampler)
	
	if err != nil {
		t.Fatalf("Error during random vector generation: %v", err)
	}

	// derive a functional key for vector y
	key, err := fhtao.DeriveKey(y, masterSecKey.BStarHat)
	if err != nil {
		t.Fatalf("Error during key derivation: %v", err)
	}

	// simulate a decryptor
	decryptor := fullysec.NewFHTAO20FromParams(fhtao.Params)

	// decryptor decrypts the inner-product without knowing
	// vectors x and y
	xy, err := decryptor.Decrypt(cipher, key, pubKey)
	if err != nil {
		t.Fatalf("Error during decryption: %v", err)
	}

	// check the correctness of the result
	xyCheck, err := x.Dot(y)

	if err != nil {
		t.Fatalf("Error during inner product calculation")
	}
	assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
	
}
