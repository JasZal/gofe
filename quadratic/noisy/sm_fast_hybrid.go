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
	"log"
	"math/big"
	"runtime"
	"sync"

	"github.com/JasZal/gofe/data"
	"github.com/JasZal/gofe/innerprod/fullysec"
	"github.com/JasZal/gofe/innerprod/noisy"
	"github.com/JasZal/gofe/internal/dlog"
	"github.com/JasZal/gofe/sample"
	"github.com/fentec-project/bn256"
)

// todo
type OTQuadParams struct {
	SecLevel   int      //k
	NumClients int      //n
	VecLen     int      //m
	BoundX     *big.Int //X
	BoundY     *big.Int //C
	BoundNoise *big.Int //Delta
	Modulus    *big.Int //modulus p
	paramsOT   *noisy.OTPRFParams
	paramsFH   *fullysec.AffineMultiIPEParams
}

// This struct contains the shared choice for parameters on which the
// functionality of the scheme depend.
type OTQuad struct {
	Params *OTQuadParams
}

// todo
type OTQuadSecKey struct {
	fhMSK *fullysec.AffineMultiIPESecKey
	nhMSK [][]byte
	otMSK [][]byte
}

type OTQuadPP struct {
	fhPP    *bn256.GT
	modulus *big.Int
}

// todo
type OTQuadEncKey struct {
	fhEncKey []data.Matrix
	nhEncKey []byte
	otEncKey []byte
}

// todo
type OTQuadDecKey struct {
	fhDecKey data.MatrixG2
	nhDecKey data.Matrix
}

// todo
type OTQuadCT struct {
	nhCT data.Vector
	otCT data.Vector
	fhCT data.MatrixG1
}

func NewOTQuad(secLevel, numClients, vecLen int, boundX, boundY, boundN *big.Int) *OTQuad {
	//use hybrid version, fhmife works best for small vecLen, nmife the contrary
	nmife := noisy.NewOTPRFModPrime(numClients, vecLen, bn256.Order, true)
	fhmife := fullysec.NewAffineMultiIPE(secLevel, numClients*vecLen, 1, boundX, boundY)

	params := &OTQuadParams{SecLevel: secLevel, NumClients: numClients,
		VecLen: vecLen, BoundX: boundX, BoundY: boundY, BoundNoise: boundN, paramsOT: nmife.Params, paramsFH: fhmife.Params,
		Modulus: nmife.Params.ModulusL}

	return &OTQuad{Params: params}
}

func NewOTQuadFromParams(params *OTQuadParams) *OTQuad {
	return &OTQuad{
		Params: params,
	}
}

// GenerateKeys generates a tripel of master secret key, encryption keys and a public key
// for the scheme. It returns an error in case keys could not be
// generated.
func (f OTQuad) GenerateKeys() (*OTQuadSecKey, []OTQuadEncKey, *OTQuadPP, error) {

	//generate keys from underlying building blocks
	//nmife (noot)
	nmife := noisy.NewOTPRFFromParams(f.Params.paramsOT)
	nmifeMSK := nmife.GenerateKeys()

	//OTP (noot):
	otmife := noisy.NewOTPRFFromParams(f.Params.paramsOT)
	otMSK := otmife.GenerateKeys()

	//FH Scheme (Datta):
	fhmife := fullysec.NewAffineMultiIPEFromParams(f.Params.paramsFH)
	fhMSK, fhPK, err := fhmife.GenerateKeys()

	if err != nil {
		return nil, nil, nil, err
	}

	//master secret key
	seckeys := OTQuadSecKey{nhMSK: nmifeMSK, fhMSK: fhMSK, otMSK: otMSK}

	//encryption keys
	enckeys := make([]OTQuadEncKey, f.Params.NumClients)

	for i := 0; i < f.Params.NumClients; i++ {
		//hybrid version, fhmife works best for m=1
		encKey := make([]data.Matrix, f.Params.VecLen)
		for j := 0; j < f.Params.VecLen; j++ {
			encKey[j] = fhMSK.BHat[(i)*f.Params.VecLen+j]
		}
		enckeys[i] = OTQuadEncKey{nhEncKey: nmifeMSK[i], fhEncKey: encKey, otEncKey: otMSK[i]}
	}

	//pp
	pp := OTQuadPP{fhPP: fhPK, modulus: bn256.Order}
	return &seckeys, enckeys, &pp, nil

}

// Encrypt encrypts an input vectors x associated with a slot i with the
// encryptio key ek_i. It returns the appropriate ciphertext.
// If ciphertext could not be generated, it returns an error.
func (f OTQuad) Encrypt(ek OTQuadEncKey, x data.Vector, label []byte) (*OTQuadCT, error) {

	// build ot.ct_i
	nmife := noisy.NewOTPRFFromParams(f.Params.paramsOT)
	ctNMIFE, err := nmife.Encrypt(x, label, ek.nhEncKey)

	if err != nil {
		return nil, err
	}

	//one-time pad enc, building ct_{i,j}
	otmife := noisy.NewOTPRFFromParams(f.Params.paramsOT)

	//gives us j individual encryptions of x_ij
	ctOTMIFE, err := otmife.Encrypt(x, label, ek.otEncKey)
	if err != nil {
		return nil, err
	}

	//hybrid version, fhmife works best for m=1
	fhmife := fullysec.NewAffineMultiIPEFromParams(f.Params.paramsFH)
	ctFHMIFE := make([]data.VectorG1, f.Params.VecLen)
	for j := 0; j < f.Params.VecLen; j++ {
		ctFHMIFE[j], err = fhmife.Encrypt(data.NewConstantVector(1, x[j]), ek.fhEncKey[j])
		if err != nil {
			return nil, err
		}
	}

	return &OTQuadCT{nhCT: ctNMIFE, otCT: ctOTMIFE, fhCT: ctFHMIFE}, nil
}

// DeriveKey derives the functional encryption key for a quadratic function associated with a true quadratic term, a linear term and a constant term.
// It returns an error if the key could not be derived.
func (f OTQuad) DeriveKey(yQuad [][]data.Matrix, yLin data.Matrix, yCon, noise *big.Int, label []byte, msk *OTQuadSecKey) (*OTQuadDecKey, error) {
	maxWorkers := runtime.NumCPU()

	var err error

	//make partial keys for NMIFE
	nhmife := noisy.NewOTPRFFromParams(f.Params.paramsOT)
	otmife := noisy.NewOTPRFFromParams(f.Params.paramsOT)
	nhdeckey := data.NewConstantMatrix(f.Params.NumClients, f.Params.VecLen, big.NewInt(0))

	//exract zeta values

	zeta := data.NewConstantMatrix(f.Params.NumClients, f.Params.VecLen, big.NewInt(0))
	for i := 0; i < f.Params.NumClients; i++ {
		zeta[i], err = otmife.ReturnZeta(label, msk.otMSK[i])
		if err != nil {
			return nil, err
		}
	}

	//sample random noise values for OTP masking
	sampler := sample.NewUniform(f.Params.Modulus)
	nu := data.NewConstantMatrix(f.Params.NumClients, f.Params.VecLen, big.NewInt(0))

	//build coefficients for fh scheme
	//yFH_ij = \sum_{k,l}y[klij]zeta[kl] + nu_{i,j} - y[00ij]

	// hybrid version, fh works best for m = 1
	yFH := data.NewConstantMatrix(f.Params.NumClients*f.Params.VecLen, 1, big.NewInt(0))

	conFH := new(big.Int).Set(new(big.Int).Neg(new(big.Int).Add(yCon, noise)))
	conFH.Mod(conFH, f.Params.Modulus)

	var wg sync.WaitGroup
	workerPool := make(chan struct{}, maxWorkers)
	var conFhMu sync.Mutex // to safely merge localConFH into globalConFH

	for i := 0; i < f.Params.NumClients; i++ {
		wg.Add(1)
		workerPool <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-workerPool }()

			localConFH := new(big.Int)

			for j := 0; j < f.Params.VecLen; j++ {
				nu[i][j], err = sampler.Sample()
				if err != nil {
					fmt.Println("Error sampling nu:", err)
					return
				}

				for k := 0; k < f.Params.NumClients; k++ {
					for l := 0; l < f.Params.VecLen; l++ {
						yFH[(i)*f.Params.VecLen+j][0].Add(yFH[(i)*f.Params.VecLen+j][0], new(big.Int).Mul(yQuad[k][l][i][j], zeta[k][l]))
					}
				}

				yFH[(i)*f.Params.VecLen+j][0].Mod(new(big.Int).Sub(new(big.Int).Add(yFH[(i)*f.Params.VecLen+j][0], nu[i][j]), yLin[i][j]), f.Params.Modulus)
				localConFH.Mod(new(big.Int).Add(localConFH, new(big.Int).Mul(nu[i][j], zeta[i][j])), f.Params.Modulus)

				//build decryption key for noot for z_ij
				nhdeckey[i][j], err = nhmife.DeriveKey(msk.nhMSK, yQuad[i][j], nu[i][j], label, maxWorkers)
				if err != nil {
					fmt.Println("Error deriving key:", err)
				}
			}

			// Safely merge localConFH into globalConFH
			conFhMu.Lock()
			conFH.Add(conFH, localConFH)
			conFH.Mod(conFH, f.Params.Modulus)
			conFhMu.Unlock()
		}(i)
	}
	wg.Wait()

	//make key for FH MIFE
	fhmife := fullysec.NewAffineMultiIPEFromParams(f.Params.paramsFH)

	fhdk, err := fhmife.DeriveKey(yFH, msk.fhMSK, conFH)
	if err != nil {
		return nil, err
	}

	return &OTQuadDecKey{nhDecKey: nhdeckey, fhDecKey: fhdk}, nil
}

// Decrypt first evaluates the decryption algorithm within the target group and then performs an exhaustive search step to find the discrete logarithm
func (f OTQuad) Decrypt(dk *OTQuadDecKey, yQuad [][]data.Matrix, ct []*OTQuadCT, pp *OTQuadPP) (*big.Int, error) {
	r, err := f.DecryptWOSearch(dk, yQuad, ct, pp)
	if err != nil {
		return nil, err
	}

	//quad
	b := (f.Params.VecLen * f.Params.VecLen * f.Params.NumClients * f.Params.NumClients)
	bound := new(big.Int).Mul(big.NewInt(int64(b)), new(big.Int).Mul(f.Params.BoundX, f.Params.BoundX))
	bound.Mul(bound, f.Params.BoundY)
	//lin
	bound.Add(bound, new(big.Int).Mul(big.NewInt(int64(f.Params.VecLen*f.Params.NumClients)), new(big.Int).Mul(f.Params.BoundX, f.Params.BoundY)))
	//cons
	bound.Add(bound, new(big.Int).Add(f.Params.BoundNoise, f.Params.BoundY))

	dec, err := dlog.NewCalc().InBN256().WithNeg().WithBound(bound).BabyStepGiantStep(r, pp.fhPP)

	return dec, err
}

//todo parallelisieren

func (f OTQuad) DecryptWOSearch(dk *OTQuadDecKey, yQuad [][]data.Matrix, ct []*OTQuadCT, pp *OTQuadPP) (*bn256.GT, error) {
	var err error

	//decrypt NMIFE scheme
	nhmife := noisy.NewOTPRFFromParams(f.Params.paramsOT)
	z := data.NewConstantMatrix(f.Params.NumClients, f.Params.VecLen, big.NewInt(0))

	//generate slice of nhCT
	nhCTs := make([]data.Vector, f.Params.NumClients)
	for i := 0; i < f.Params.NumClients; i++ {
		nhCTs[i] = ct[i].nhCT
	}

	//decrypt nOPT (noot) to generate z_ij values
	var wg sync.WaitGroup
	maxWorkers := runtime.NumCPU()
	workerPool := make(chan struct{}, maxWorkers)

	for i := 0; i < f.Params.NumClients; i++ {
		for j := 0; j < f.Params.VecLen; j++ {
			wg.Add(1)
			workerPool <- struct{}{}
			go func(i, j int) {
				defer wg.Done()
				defer func() { <-workerPool }()

				var err error
				z[i][j], err = nhmife.Decrypt(nhCTs, dk.nhDecKey[i][j], yQuad[i][j])
				if err != nil {
					log.Println("Error decrypting z:", err)
					return
				}
				z[i][j].Mod(z[i][j], f.Params.Modulus)
			}(i, j)
		}
	}
	wg.Wait()

	//use skalar multiplicaty
	// z_ij * otct_ij
	sum := big.NewInt(0)

	for i := 0; i < f.Params.NumClients; i++ {
		for j := 0; j < f.Params.VecLen; j++ {
			sum.Mod(new(big.Int).Add(sum, new(big.Int).Mod(new(big.Int).Mul(ct[i].otCT[j], z[i][j]), f.Params.Modulus)), f.Params.Modulus)
		}
	}

	r_1 := new(bn256.GT).ScalarMult(pp.fhPP, sum)

	// generate slice of fhCT
	// hybrid version, fh works best for m = 1
	fhCTs := make(data.MatrixG1, f.Params.NumClients*f.Params.VecLen)
	for i := 0; i < f.Params.NumClients; i++ {
		for j := 0; j < f.Params.VecLen; j++ {
			fhCTs[i*f.Params.VecLen+j] = ct[i].fhCT[j]
		}

	}

	//decrypt
	fhmife := fullysec.NewAffineMultiIPEFromParams(f.Params.paramsFH)
	r_2 := fhmife.DecryptWOSearch(fhCTs, dk.fhDecKey, pp.fhPP)

	r := new(bn256.GT).Add(r_1, new(bn256.GT).Neg(r_2))
	return r, err
}
