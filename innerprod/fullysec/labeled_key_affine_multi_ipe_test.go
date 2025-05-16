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
	"time"

	"github.com/JasZal/gofe/data"
	"github.com/JasZal/gofe/innerprod/fullysec"
	"github.com/JasZal/gofe/sample"
)

func TestLKADOT(t *testing.T) {
	// choose the parameters for the scheme
	secLevel := 2
	vecLen := 1
	numClient := 1000
	bound := big.NewInt(128)

	// build the scheme
	f := fullysec.NewLKADOT(secLevel, numClient, vecLen, bound, bound)

	// generate master secret key and public key
	start := time.Now()
	masterSecKey, pubKey, err := f.GenerateKeys()
	UNUSED(pubKey)
	fmt.Printf("time Setup: %v\n", time.Since(start))
	if err != nil {
		t.Fatalf("Error during keys generation: %v", err)
	}

	// sample vectors that will be encrypted
	label := make([]byte, 16)
	sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(bound), big.NewInt(1)), bound)
	x := make(data.Matrix, numClient)
	for i := 0; i < numClient; i++ {
		x[i], err = data.NewRandomVector(vecLen, sampler)
		if err != nil {
			t.Fatalf("Error during random vector generation: %v", err)
		}

	}

	// simulate different clients (encryptors which should be given a part of the master key)
	// and encrypt their vectors

	cipher := make(data.MatrixG1, numClient)
	clients := make([]*fullysec.LKADOT, numClient)
	for i := 0; i < numClient; i++ {

		clients[i] = fullysec.NewLKADOTFromParams(f.Params)
		start = time.Now()
		cipher[i], err = clients[i].Encrypt(x[i], masterSecKey.BHat[i], masterSecKey.PRFkey[i], label)
		if i == 0 {
			fmt.Printf("time Enc one: %v\n", time.Since(start))
		}
		if err != nil {
			t.Fatalf("Error during encryption: %v", err)
		}
	}

	// sample inner product vectors and put them in a matrix
	y := make(data.Matrix, numClient)
	for i := 0; i < numClient; i++ {
		y[i], err = data.NewRandomVector(vecLen, sampler)
		if err != nil {
			t.Fatalf("Error during random vector generation: %v", err)
		}
	}

	c, _ := sampler.Sample()
	//c := big.NewInt(0)

	// derive a functional key for vector y
	start = time.Now()
	key, err := f.DeriveKey(y, masterSecKey, c, label)
	fmt.Printf("time KeyGen: %v\n", time.Since(start))
	if err != nil {
		t.Fatalf("Error during key derivation: %v", err)
	}

	UNUSED(key)
	// // simulate a decryptor
	// decryptor := fullysec.NewLKADOTFromParams(f.Params)

	// // check the correctness of the result
	// xyCheck, err := x.Dot(y)
	// xyCheck.Add(xyCheck, c)
	// if err != nil {
	// 	t.Fatalf("Error during inner product calculation")
	// }
	// fmt.Printf("true result: %v\n", xyCheck)

	// // decryptor decrypts the inner-product without knowing
	// // vectors x and y
	// xy, err := decryptor.Decrypt(cipher, key, pubKey)
	// if err != nil {
	// 	t.Fatalf("Error during decryption: %v", err)
	// }
	// fmt.Printf("computed result: %v\n", xy)
	// assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
}

func UNUSED(values ...interface{}) {

}
