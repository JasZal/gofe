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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/JasZal/gofe/data"
)

var rejsampling bool

// Todo
type OTPRFParams struct {
	// number of encryptors
	NumClients int
	VecLen     int
	BoundX     *big.Int
	BoundY     *big.Int
	BoundN     *big.Int
	ModulusL   *big.Int
	Lambda     int //security parameter in bytes
	ZetaBytes  int
}

// ToDo
type OTPRF struct {
	Params *OTPRFParams
}

// NewOTPRF configures a new instance of the scheme.
// It accepts the number of slots (encryptors), the length of
// input vectors m, the bit length of the modulus (we are
// operating in the Z_p group), and a bound by which coordinates
// of input vectors are bounded.
//

func NewOTPRF(numclients, veclen int, boundX, boundY, boundN *big.Int) *OTPRF {
	b := new(big.Int).Add(new(big.Int).Mul(boundX, new(big.Int).Mul(boundY, big.NewInt((int64)(numclients)*(int64)(veclen)))), new(big.Int).Add(big.NewInt(1), boundN))
	b.Mul(b, big.NewInt(4))

	x := int(math.Ceil(float64(b.BitLen()) / 8.0)) // for bytes

	mod := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(8*x)), nil)

	//fmt.Println("n:", numclients, " m:", veclen, "Bound res:", b, "needed byte: ", x, "mod: ", mod)

	params := &OTPRFParams{NumClients: numclients,
		VecLen: veclen, ModulusL: mod, BoundX: boundX, BoundY: boundY, BoundN: boundN, ZetaBytes: int(x)}
	return &OTPRF{Params: params}

}

func LargestPrimeBetw(p, x *big.Int, confidence int) *big.Int {
	//y = x - 1
	y := new(big.Int).Sub(x, big.NewInt(1))

	// check if y is a prime, as long as y > p
	for y.Cmp(p) > 0 {
		if y.ProbablyPrime(confidence) {
			return y
		}
		y.Sub(y, big.NewInt(1))
	}
	return p
}

// NewOTPRFMod configures a new instance of the scheme, accepting the number of slots and
// the length of input vectors.
// and a prime modulus for the Z_p group.
// if mod is not fix, it sets the modulus to the biggest prime that is smaller, to optimize rejsampling
func NewOTPRFModPrime(numclients, veclen int, modulus *big.Int, fixedmod bool) *OTPRF {

	floatmod, _ := new(big.Float).SetInt(modulus).Float64()
	x := int(math.Ceil(math.Log2(floatmod) / 8))

	var mod *big.Int
	if fixedmod {
		mod = new(big.Int).Set(modulus)
	} else {
		mod = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(8*x)), nil)
		//modulus is not a power of 2
		if mod.Cmp(modulus) == 1 {
			//find biggest smaller prime, to avoid unneccessary rejsampling
			//20 = confidence value for primes
			mod = LargestPrimeBetw(modulus, mod, 20)
			rejsampling = true
		}
	}

	//fmt.Println("prim mod: ", modulus, "needed bytes: ", x, "mod:", mod)

	params := &OTPRFParams{NumClients: numclients,
		VecLen: veclen, ModulusL: mod, ZetaBytes: int(x)}
	return &OTPRF{Params: params}

}

// todo
func NewOTPRFFromParams(params *OTPRFParams) *OTPRF {
	return &OTPRF{
		Params: params,
	}
}

func (sm *OTPRF) GetParams() *OTPRFParams {
	return sm.Params
}

// GenerateMasterKeys generates matrices comprised of master secret
// keys and encryption keys for the scheme.
//
// It returns an error in case  keys could not be generated.
func (sm *OTPRF) GenerateKeys() [][]byte {

	msk := make([][]byte, sm.Params.NumClients)

	for i := 0; i < sm.Params.NumClients; i++ {
		msk[i] = make([]byte, 32)
		rand.Read(msk[i]) //secure?
	}

	return msk
}

func (sm *OTPRF) ReturnZeta(label []byte, secKey []byte) (data.Vector, error) {
	zeta := make(data.Vector, sm.Params.VecLen)
	var err error
	//generate and initialize PRF
	c, err := aes.NewCipher(secKey)
	if err != nil {
		fmt.Println("error creating aes block cipher", err)
		return nil, err
	}
	stream := cipher.NewOFB(c, label)

	for j := 0; j < sm.Params.VecLen; {
		ks := make([]byte, sm.Params.ZetaBytes)

		stream.XORKeyStream(ks, ks)

		zeta[j] = new(big.Int).Add(big.NewInt(0), new(big.Int).SetBytes(ks))
		//check if zeta[j] is <= mod
		i := zeta[j].Cmp(sm.Params.ModulusL)
		if !rejsampling || i <= 0 {
			j++
		}
	}

	return zeta, nil

}

// Encrypt generates a ciphertext from the input vector x
// It returns the ciphertext vector.
// If encryption failed, error is returned.
func (sm *OTPRF) Encrypt(x data.Vector, label []byte, secKey []byte) (data.Vector, error) {

	ct := make(data.Vector, sm.Params.VecLen)
	var err error
	//generate and initialize PRF
	c, err := aes.NewCipher(secKey)
	if err != nil {
		fmt.Println("error creating aes block cipher", err)
		return nil, err
	}
	stream := cipher.NewOFB(c, label)

	for j := 0; j < sm.Params.VecLen; {
		ks := make([]byte, sm.Params.ZetaBytes)

		stream.XORKeyStream(ks, ks)

		zeta := new(big.Int).Add(big.NewInt(0), new(big.Int).SetBytes(ks))
		//check if zeta[j] is <= mod
		if !rejsampling || zeta.Cmp(sm.Params.ModulusL) <= 0 {
			ct[j] = new(big.Int).Add(x[j], zeta)
			j++
		}
	}

	ct.Mod(sm.Params.ModulusL)

	return ct, nil
}

// DeriveKey takes master secret key and a matrix y comprised
// of input vectors, and returns the functional encryption key.
// In case the key could not be derived, it returns an error.
func (sm *OTPRF) DeriveKey(msk [][]byte, y data.Matrix, c *big.Int, label []byte, nrWorkers int) (*big.Int, error) {

	z := big.NewInt(0)

	//keystrem length = max(ceil(mx/lambda)*mx, lambda)

	var wg sync.WaitGroup
	chOut := make(chan *big.Int, sm.Params.NumClients)
	chIn := make(chan int)

	for i := 0; i < nrWorkers; i++ {
		wg.Add(1)
		go workers(sm.Params.VecLen, sm.Params.ZetaBytes, sm.Params.ModulusL, msk, y, label, chIn, chOut, &wg)

	}

	for i := 0; i < len(y); i++ {
		for j := 0; j < len(y[0]); j++ {
			if y[i][j].Cmp(big.NewInt(0)) != 0 {
				chIn <- i
				break
			}
		}

	}

	close(chIn)
	go func() {
		wg.Wait()
		close(chOut)
	}()

	for results := range chOut {
		z.Add(z, results)
		z.Mod(z, sm.Params.ModulusL)
	}

	z.Add(z, new(big.Int).Mul(c, big.NewInt(-1)))
	z.Mod(z, sm.Params.ModulusL)

	return z, nil

}

func workers(vecLen, zetaBytes int, mod *big.Int, msk [][]byte, y data.Matrix, label []byte, chIn chan int, chOut chan *big.Int, wg *sync.WaitGroup) {
	defer wg.Done()
	sum := big.NewInt(0)
	for i := range chIn {

		c, err := aes.NewCipher(msk[i])
		if err != nil {
			fmt.Println("error creating aes block cipher", err)
		}
		stream := cipher.NewOFB(c, label)

		for j := 0; j < vecLen; {
			ks := make([]byte, zetaBytes)
			stream.XORKeyStream(ks, ks)

			zeta := new(big.Int).Add(big.NewInt(0), new(big.Int).SetBytes(ks))
			//check if zeta[j] is <= mod
			if !rejsampling || zeta.Cmp(mod) <= 0 {
				sum.Add(sum, new(big.Int).Mul(zeta, y[i][j]))
				sum.Mod(sum, mod)
				j++
			}
		}

		if err != nil {
			fmt.Println("error dot product", err)
		}

	}
	chOut <- sum

}

// Decrypt accepts the matrix cipher comprised of encrypted vectors,
// functional encryption key, and a matrix y comprised of plaintext vectors.
// It returns the sum of inner products + constant.
// If decryption failed, error is returned.
func (sm *OTPRF) Decrypt(cipher []data.Vector, deckey *big.Int, y data.Matrix) (*big.Int, error) {

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
	if res.Cmp(new(big.Int).Div(sm.Params.ModulusL, big.NewInt(2))) == 1 {
		res = new(big.Int).Sub(res, sm.Params.ModulusL)
	}
	return res, nil

}
