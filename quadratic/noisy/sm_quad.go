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
	"math/big"

	"github.com/JasZal/gofe/data"
	"github.com/JasZal/gofe/innerprod/fullysec"
	"github.com/JasZal/gofe/internal/dlog"
	"github.com/JasZal/gofe/sample"
	"github.com/fentec-project/bn256"
)

// Params represents configuration parameters for the SMNH scheme instance.
// SecLevel (int): The parameter defines the security assumption of the scheme, k >= 2, MMDH_k assumption
// NumClients (int): The number of clients participating
// VecLenX (int): The length of vectors x that clients want to encrypt.
// BoundX (int): The value by which the coordinates of encrypted vectors x are bounded.
// Bound (int): The value by which the coordinates of inner product vectors y are bounded.
type SMNHParams struct {
	SecLevel   int      //k
	NumClients int      //n
	VecLen     int      //m
	BoundX     *big.Int //X
	BoundY     *big.Int //C
	BoundNoise *big.Int //Delta
}

// SMNH represents a Single Message Noise Hiding Quadratic Functional Encryption scheme
// It allows clients to encrypt vectors {x_1, ..., x_m} and derive a secret key
// based on an quadratic function, displayed as a vector c[(i,j,k,l)] and a distribution Delta, so that a decryptor can
// decrypt the sum of c[(i,j,k,l)]xi[j]xk[l] + noise where noise is sampled via the distribution Delta, without revealing
// intermediate results.
// The scheme is based on a evolved miFE scheme (DOT18: Full-Hiding (Unbounded) Multi-Input Inner Product Functional Encryption from the k-Linear Assumption) and a
//iFE scheme (TAO20: "Efficient Inner Product Functional Encryption with Full-Hiding Security")

// This struct contains the shared choice for parameters on which the
// functionality of the scheme depend.
type SMNH struct {
	Params *SMNHParams
}

// SMNHSecKey represents a master secret key in SMNH scheme.
type SMNHSecKey struct {
	IMSK  *fullysec.FHTAO20SecKey
	MiMSK *fullysec.AffineMultiIPESecKey
	u     data.Matrix
	uT    data.Matrix
	v     data.Matrix
	vT    data.Matrix
}

// SMNHEncKey represents the encryption keys in SMNH scheme
type SMNHEncKey struct {
	//ek_i = (miSKi, {uij, Tuij, vij, Tvij}, {MCT},{DMDK})
	MiSK data.Matrix
	u    data.Vector
	uT   data.Vector
	v    data.Vector
	vT   data.Vector
	MCT  data.MatrixG1
	MDK  data.MatrixG2
}

// SMNHCT represents a ciphertext in SMNH scheme.
type SMNHCT struct {
	ICT  data.MatrixG1
	IDK  data.MatrixG2
	MiCT data.VectorG1
}

// SMNHDK represents a decryption key in SMNH scheme.
type SMNHDK struct {
	C    [][]data.Matrix
	MiDK data.MatrixG2
}

// NewSMNH configures a new instance of the scheme. See struct
// SMNHParams for the description of the parameters. It returns
// a new SMNH instance.
func NewSMNH(secLevel, numClients, vecLen int, boundx, boundy, boundn *big.Int) *SMNH {
	params := &SMNHParams{SecLevel: secLevel, NumClients: numClients,
		VecLen: vecLen, BoundX: boundx, BoundY: boundy, BoundNoise: boundn}
	return &SMNH{Params: params}
}

// NewSMNHFromParams takes configuration parameters of an existing
// SMNH scheme instance, and reconstructs the scheme with the same
// configuration parameters. It returns a new SMNH instance.
func NewSMNHFromParams(params *SMNHParams) *SMNH {
	return &SMNH{
		Params: params,
	}
}

// GenerateKeys generates a triple of master secret key, encryption keys and a public key
// for the scheme. It returns an error in case keys could not be
// generated.
func (f SMNH) GenerateKeys() (*SMNHSecKey, []*SMNHEncKey, *bn256.GT, error) {

	sampler := sample.NewUniformRange(big.NewInt(1), bn256.Order)
	mu, err := sampler.Sample()

	if err != nil {
		return nil, nil, nil, err
	}

	iFE := fullysec.NewFHTAO20(f.Params.SecLevel, f.Params.VecLen+4, f.Params.BoundX, f.Params.BoundY)
	imsk, _, err := iFE.GenerateKeysWOS(mu)
	if err != nil {
		return nil, nil, nil, err
	}

	miFE := fullysec.NewAffineMultiIPE(f.Params.SecLevel, f.Params.NumClients, 3, f.Params.BoundX, f.Params.BoundY)

	mimsk, pp, err := miFE.GenerateKeysWOS(mu)
	if err != nil {
		return nil, nil, nil, err
	}

	u, err := data.NewRandomMatrix(f.Params.NumClients, f.Params.VecLen, sampler)

	if err != nil {
		return nil, nil, nil, err
	}

	uT, err := data.NewRandomMatrix(f.Params.NumClients, f.Params.VecLen, sampler)

	if err != nil {
		return nil, nil, nil, err
	}

	v, err := data.NewRandomMatrix(f.Params.NumClients, f.Params.VecLen, sampler)

	if err != nil {
		return nil, nil, nil, err
	}

	vT, err := data.NewRandomMatrix(f.Params.NumClients, f.Params.VecLen, sampler)

	if err != nil {
		return nil, nil, nil, err
	}

	msk := SMNHSecKey{IMSK: imsk, MiMSK: mimsk, u: u, uT: uT, v: v, vT: vT}

	//ecnryption keys

	enckeys := make([]*SMNHEncKey, f.Params.NumClients)

	mct_plain := data.NewConstantMatrix(4, f.Params.VecLen+4, big.NewInt(0))
	//mct0 = (0,...,0)
	//todo: potentiell mehr mct
	//mct1 = (1,0,0,0,0m)
	mct_plain[1][0] = big.NewInt(1)
	//mct2 = (0,0,1,0,0m)
	mct_plain[2][2] = big.NewInt(1)
	//mct3 = (0,0,0,1,0m)
	mct_plain[3][3] = big.NewInt(1)

	mct := make([]data.VectorG1, len(mct_plain))
	mdk := make([]data.VectorG2, len(mct_plain))

	for j := 0; j < len(mct_plain); j++ {

		mct[j], err = iFE.Encrypt(mct_plain[j], msk.IMSK.BHat)
		if err != nil {
			return nil, nil, nil, err
		}

		mdk[j], err = iFE.DeriveKey(mct_plain[j], msk.IMSK.BStarHat)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	for i := 0; i < f.Params.NumClients; i++ {
		enckeys[i] = &SMNHEncKey{MiSK: mimsk.BHat[i], u: u[i], uT: uT[i], v: v[i], vT: vT[i], MCT: mct, MDK: mdk}
	}

	return &msk, enckeys, pp, nil

}

// todo
func (f SMNH) Encrypt(ek *SMNHEncKey, x data.Vector) (*SMNHCT, error) {

	ict := make(data.MatrixG1, f.Params.VecLen)
	idk := make(data.MatrixG2, f.Params.VecLen)

	sampler := sample.NewUniform(bn256.Order)

	r, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	t, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	gamma, err := data.NewRandomVector((2), sampler)

	for j := 0; j < f.Params.VecLen; j++ {
		//ictj = cj*MCT1 + ruij*MCT2 + vij*MCT3 + sum(gamma*MCT0)
		ict[j] = ek.MCT[1].MulScalar(x[j]).Add(ek.MCT[2].MulScalar(new(big.Int).Mul(r, ek.u[j]))).Add(ek.MCT[3].MulScalar(ek.v[j]))
		idk[j] = ek.MDK[1].MulScalar(x[j]).Add(ek.MDK[2].MulScalar(ek.uT[j])).Add(ek.MDK[3].MulScalar(new(big.Int).Mul(t, ek.vT[j])))

		ict[j].Add(ek.MCT[0].MulScalar(gamma[0]))
		idk[j].Add(ek.MDK[0].MulScalar(gamma[1]))

	}

	miFE := fullysec.NewAffineMultiIPEFromParams(&fullysec.AffineMultiIPEParams{SecLevel: f.Params.SecLevel, NumClients: f.Params.NumClients, VecLen: 3,
		BoundX: f.Params.BoundX, BoundY: f.Params.BoundY})

	fmg := data.NewConstantVector(3, big.NewInt(0))

	fmg[0] = r
	fmg[1] = t

	mict, err := miFE.Encrypt(fmg, ek.MiSK)
	if err != nil {
		return nil, err
	}
	return &SMNHCT{ICT: ict, IDK: idk, MiCT: mict}, nil
}

// DeriveKey takes a vector c who represents a quadratic function
// master secret key, and returns the functional encryption key. That is
// a key that for encrypted x_1, ..., y_n  allows to calculate the sum of
// c(ki,j,k,l)x_i[j]x_k[l] + noise.  In case the key could not
// be derived, it returns an error.
func (f SMNH) DeriveKey(c [][]data.Matrix, noise *big.Int, msk *SMNHSecKey) (*SMNHDK, error) {

	//check if c is correct build
	//todo

	//invert noise
	noise = new(big.Int).Mul(noise, big.NewInt(-1))

	fT := make(data.Matrix, f.Params.NumClients)

	for i := 0; i < f.Params.NumClients; i++ {
		fT[i] = data.NewConstantVector(3+f.Params.VecLen*f.Params.VecLen, big.NewInt(0))

		for j := 0; j < f.Params.VecLen; j++ {
			for k := 0; k < f.Params.NumClients; k++ {
				for l := 0; l < f.Params.VecLen; l++ {
					fT[i][0].Add(fT[i][0], new(big.Int).Mul(c[i][j][k][l].Mod(c[i][j][k][l], bn256.Order), new(big.Int).Mul(msk.u[i][j], msk.uT[k][l])))
					fT[i][1].Add(fT[i][1], new(big.Int).Mul(c[k][l][i][j].Mod(c[k][l][i][j], bn256.Order), new(big.Int).Mul(msk.v[k][l], msk.vT[i][j])))
				}
			}
		}

	}

	miFE := fullysec.NewAffineMultiIPEFromParams(&fullysec.AffineMultiIPEParams{SecLevel: f.Params.SecLevel, NumClients: f.Params.NumClients, VecLen: 3,
		BoundX: f.Params.BoundX, BoundY: f.Params.BoundY})

	midk, err := miFE.DeriveKey(fT, msk.MiMSK, noise)
	if err != nil {
		return nil, err
	}

	return &SMNHDK{C: c, MiDK: midk}, nil
}

// Decrypt accepts the ciphertext as a encryption of vectors
// x_1,...,x_m and a functional encryption key corresponding to  a vector c.
// It returns the sum of c(ki,j,k,l)x_i[j]x_k[l].   If decryption
// failed, an error is returned.
func (f *SMNH) Decrypt(cipher []*SMNHCT, dk *SMNHDK, boundRes *big.Int, pubKey *bn256.GT) (*big.Int, error) {

	iFE := fullysec.NewFHTAO20FromParams(&fullysec.FHTAO20Params{SecLevel: f.Params.SecLevel, VecLen: f.Params.VecLen + 4, BoundX: f.Params.BoundX, BoundY: f.Params.BoundY})

	miFE := fullysec.NewAffineMultiIPEFromParams(&fullysec.AffineMultiIPEParams{SecLevel: f.Params.SecLevel, NumClients: f.Params.NumClients, VecLen: 3,
		BoundX: f.Params.BoundX, BoundY: f.Params.BoundY})

	z1 := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	ciphermife := make(data.MatrixG1, f.Params.NumClients)

	for i := 0; i < f.Params.NumClients; i++ {
		ciphermife[i] = cipher[i].MiCT
		for k := 0; k < f.Params.NumClients; k++ {

			for j := 0; j < f.Params.VecLen; j++ {
				for l := 0; l < f.Params.VecLen; l++ {
					if dk.C[i][j][k][l].Cmp(big.NewInt(0)) != 0 {
						z1.Add(z1, new(bn256.GT).ScalarMult(iFE.DecryptWOSearch(cipher[i].ICT[j], cipher[k].IDK[l], pubKey), dk.C[i][j][k][l]))
					}
				}
			}
		}
	}

	z3 := miFE.DecryptWOSearch(ciphermife, dk.MiDK, pubKey)
	z := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	z.Add(z1, new(bn256.GT).Neg(z3))

	var bound *big.Int
	if boundRes.Cmp(big.NewInt(0)) == 0 {
		b := (f.Params.VecLen * f.Params.VecLen * f.Params.NumClients * f.Params.NumClients) / 2
		bound = new(big.Int).Mul(big.NewInt(int64(b)), new(big.Int).Mul(f.Params.BoundX, f.Params.BoundX))
		bound.Mul(bound, f.Params.BoundY)
		bound.Add(bound, f.Params.BoundNoise)
	} else {
		bound = boundRes
	}

	dec, err := dlog.NewCalc().InBN256().WithNeg().WithBound(bound).BabyStepGiantStep(z, pubKey)

	return dec, err
}

// Decrypt accepts the ciphertext as a encryption of vectors
// x_1,...,x_m and a functional encryption key corresponding to  a vector c.
// It returns the sum of c(ki,j,k,l)x_i[j]x_k[l].   If decryption
// failed, an error is returned.
func (f *SMNH) DecryptScaling(cipher []*SMNHCT, dk *SMNHDK, maxSum int, s *big.Int, pubKey *bn256.GT) (*big.Int, error) {

	iFE := fullysec.NewFHTAO20FromParams(&fullysec.FHTAO20Params{SecLevel: f.Params.SecLevel, VecLen: f.Params.VecLen + 4, BoundX: f.Params.BoundX, BoundY: f.Params.BoundY})

	miFE := fullysec.NewAffineMultiIPEFromParams(&fullysec.AffineMultiIPEParams{SecLevel: f.Params.SecLevel, NumClients: f.Params.NumClients, VecLen: 3,
		BoundX: f.Params.BoundX, BoundY: f.Params.BoundY})

	z1 := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	ciphermife := make(data.MatrixG1, f.Params.NumClients)

	for i := 0; i < f.Params.NumClients; i++ {
		ciphermife[i] = cipher[i].MiCT
		for k := 0; k < f.Params.NumClients; k++ {

			for j := 0; j < f.Params.VecLen; j++ {
				for l := 0; l < f.Params.VecLen; l++ {
					if dk.C[i][j][k][l].Cmp(big.NewInt(0)) != 0 {
						z1.Add(z1, new(bn256.GT).ScalarMult(iFE.DecryptWOSearch(cipher[i].ICT[j], cipher[k].IDK[l], pubKey), dk.C[i][j][k][l]))
					}
				}
			}
		}
	}

	z3 := miFE.DecryptWOSearch(ciphermife, dk.MiDK, pubKey)
	z := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	z.Add(z1, new(bn256.GT).Neg(z3))

	bound := new(big.Int).Mul(big.NewInt(int64(maxSum)), new(big.Int).Mul(new(big.Int).Div(f.Params.BoundX, s), new(big.Int).Div(f.Params.BoundX, s)))
	bound.Mul(bound, f.Params.BoundY)
	bound.Add(bound, f.Params.BoundNoise)

	dec, err := dlog.NewCalc().InBN256().WithNeg().WithBound(bound).BabyStepGiantStep(z, pubKey)

	return dec, err
}
