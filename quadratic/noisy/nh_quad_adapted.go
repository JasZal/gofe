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
	"errors"
	"math/big"

	"github.com/JasZal/gofe/data"
	"github.com/JasZal/gofe/innerprod/fullysec"
	"github.com/JasZal/gofe/internal/dlog"
	"github.com/JasZal/gofe/sample"
	"github.com/fentec-project/bn256"
)

// Params represents configuration parameters for the NHQuadAdap scheme instance.
// SecLevel (int): The parameter defines the security assumption of the scheme, k >= 2, MMDH_k assumption
// NumClients (int): The number of clients participating
// VecLenX (int): The length of vectors x that clients want to encrypt.
// BoundX (int): The value by which the coordinates of encrypted vectors x are bounded.
// Bound (int): The value by which the coordinates of inner product vectors y are bounded.
type NHQuadAdapParams struct {
	SecLevel   int      //k
	NumClients int      //n
	VecLen     int      //m = m'^2+ m' + 1
	BoundX     *big.Int //X
	BoundY     *big.Int //C
	BoundNoise *big.Int //Delta
}

// NHQuadAdapAdap represents a Noise Hiding Quadratic Functional Encryption scheme
// It allows clients to encrypt vectors {x_1, ..., x_m} and derive a secret key
// based on an quadratic function, displayed as a vector c[(i,j,k,l)] and a distribution Delta, so that a decryptor can
// decrypt the sum of c[(i,j,k,l)]xi[j]xk[l] + noise where noise is sampled via the distribution Delta, without revealing
// intermediate results.
// The scheme is based on a mixed-group inner product functional encryption scheme (AGT: "Multi-Input Quadratic Functional Encryption from Pairings") and an
//iFE scheme (TAO20: "Efficient Inner Product Functional Encryption with Full-Hiding Security")

// This struct contains the shared choice for parameters on which the
// functionality of the scheme depend.
type NHQuadAdap struct {
	Params *NHQuadAdapParams
}

// NHQuadAdapSecKey represents a master secret key in NHQuadAdap scheme.
type NHQuadAdapSecKey struct {
	IMSK1 *fullysec.FHTAO20SecKey
	IMSK2 *fullysec.FHTAO20SecKey
	MgMSK *fullysec.FHMGIPESecKey
	w     [][]data.Matrix
	u     data.Matrix
	uT    data.Matrix
	v     data.Matrix
	vT    data.Matrix
}

// NHQuadAdapEncKey represents the encryption keys in NHQuadAdap scheme
type NHQuadAdapEncKey struct {
	MgSK      *fullysec.FHMGIPEEncKey
	u         data.Vector
	uT        data.Vector
	v         data.Vector
	vT        data.Vector
	w         data.Matrix
	MCT       data.MatrixG1
	MDK       data.MatrixG2
	MCTSingle data.MatrixG1
	MDKSingle data.MatrixG2
}

// NHQuadAdapCT represents a ciphertext in NHQuadAdap scheme.
type NHQuadAdapCT struct {
	ICT       data.MatrixG1
	IDK       data.MatrixG2
	ICTSingle data.VectorG1
	IDKSingle data.VectorG2
	MgCT      *fullysec.FHMGIPECT
}

// NHQuadAdapDK represents a decryption key in NHQuadAdap scheme.
type NHQuadAdapDK struct {
	C     [][]data.Matrix
	MgDK  *fullysec.FHMGIPEDK
	Sigma data.Matrix
}

// NewNHQuadAdap configures a new instance of the scheme. See struct
// NHQuadAdapParams for the description of the parameters. It returns
// a new NHQuadAdap instance.
func NewNHQuadAdap(secLevel, numClients, vecLen int, boundx, boundy, boundn *big.Int) *NHQuadAdap {
	params := &NHQuadAdapParams{SecLevel: secLevel, NumClients: numClients,
		VecLen: vecLen, BoundX: boundx, BoundY: boundy, BoundNoise: boundn}
	return &NHQuadAdap{Params: params}
}

// NewNHQuadAdapFromParams takes configuration parameters of an existing
// NHQuadAdap scheme instance, and reconstructs the scheme with the same
// configuration parameters. It returns a new NHQuadAdap instance.
func NewNHQuadAdapFromParams(params *NHQuadAdapParams) *NHQuadAdap {
	return &NHQuadAdap{
		Params: params,
	}
}

// GenerateKeys generates a triple of master secret key, encryption keys and a public key
// for the scheme. It returns an error in case keys could not be
// generated.
func (f NHQuadAdap) GenerateKeys() (*NHQuadAdapSecKey, []*NHQuadAdapEncKey, *bn256.GT, error) {

	sampler := sample.NewUniformRange(big.NewInt(1), bn256.Order)
	mu, err := sampler.Sample()

	if err != nil {
		return nil, nil, nil, err
	}

	iFE := fullysec.NewFHTAO20(f.Params.SecLevel, f.Params.VecLen*f.Params.NumClients+3*f.Params.VecLen+4, f.Params.BoundX, f.Params.BoundY)
	imsk1, _, err := iFE.GenerateKeysWOS(mu)
	if err != nil {
		return nil, nil, nil, err
	}

	iFE2 := fullysec.NewFHTAO20(f.Params.SecLevel, 2, f.Params.BoundX, f.Params.BoundY)
	imsk2, _, err := iFE2.GenerateKeysWOS(mu)
	if err != nil {
		return nil, nil, nil, err
	}

	mgFE := fullysec.NewFHMGIPE(f.Params.SecLevel, f.Params.NumClients, f.Params.VecLen*f.Params.VecLen*f.Params.NumClients+3, 1, f.Params.BoundX, f.Params.BoundX, f.Params.BoundY, f.Params.BoundY)

	mgmsk, mgenck, pp, err := mgFE.GenerateKeysWOS(mu)
	if err != nil {
		return nil, nil, nil, err
	}

	w := make([][]data.Matrix, f.Params.NumClients) //w(i,j,k,l) , i,k \in [n], j,l\in[m]
	for i := 0; i < f.Params.NumClients; i++ {
		w[i] = make([]data.Matrix, f.Params.VecLen)
		for j := 0; j < f.Params.VecLen; j++ {
			w[i][j], err = data.NewRandomMatrix(f.Params.NumClients, f.Params.VecLen, sampler)
			if err != nil {
				return nil, nil, nil, err
			}
		}
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

	msk := NHQuadAdapSecKey{IMSK1: imsk1, IMSK2: imsk2, MgMSK: mgmsk, w: w, u: u, uT: uT, v: v, vT: vT}

	//ecnryption keys
	enckeys := make([]*NHQuadAdapEncKey, f.Params.NumClients)

	//generate mct, mdk
	master_plain := data.NewConstantMatrix(f.Params.NumClients*f.Params.VecLen+4, 3*f.Params.VecLen+4+f.Params.NumClients*f.Params.VecLen, big.NewInt(0))
	//mct0 = (0,...,0)
	//mct1 = (1,0,0nm,0,0,03m)
	master_plain[1][0] = big.NewInt(1)
	//mct2 = (0,0,1,0nm-1,0, 0,03m) ...
	for i := 0; i < f.Params.NumClients*f.Params.VecLen; i++ {
		master_plain[2+i][2+i] = big.NewInt(1)
	}
	//mct = (0,0,0nm, 0,1,03m)
	master_plain[f.Params.NumClients*f.Params.VecLen+2][f.Params.NumClients*f.Params.VecLen+2] = big.NewInt(1)
	master_plain[f.Params.NumClients*f.Params.VecLen+3][f.Params.NumClients*f.Params.VecLen+3] = big.NewInt(1)

	mct := make([]data.VectorG1, len(master_plain))
	mdk := make([]data.VectorG2, len(master_plain))

	for j := 0; j < len(master_plain); j++ {

		mct[j], err = iFE.Encrypt(master_plain[j], msk.IMSK1.BHat)
		if err != nil {
			return nil, nil, nil, err
		}

		mdk[j], err = iFE.DeriveKey(master_plain[j], msk.IMSK1.BStarHat)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	mctSingle := make([]data.VectorG1, 2)
	mdkSingle := make([]data.VectorG2, 2)

	plain := data.NewConstantVector(2, big.NewInt(0))

	mctSingle[0], err = iFE2.Encrypt(plain, msk.IMSK2.BHat)
	if err != nil {
		return nil, nil, nil, err
	}
	mdkSingle[0], err = iFE2.DeriveKey(plain, msk.IMSK2.BStarHat)
	if err != nil {
		return nil, nil, nil, err
	}

	plain[0] = big.NewInt(1)
	mctSingle[1], err = iFE2.Encrypt(plain, msk.IMSK2.BHat)
	if err != nil {
		return nil, nil, nil, err
	}
	mdkSingle[1], err = iFE2.DeriveKey(plain, msk.IMSK2.BStarHat)
	if err != nil {
		return nil, nil, nil, err
	}

	for i := 0; i < f.Params.NumClients; i++ {

		wi := data.NewConstantMatrix(f.Params.VecLen, f.Params.NumClients*f.Params.VecLen, big.NewInt(0))
		for j := 0; j < f.Params.VecLen; j++ {
			for k := 0; k < f.Params.NumClients; k++ {
				for l := 0; l < f.Params.VecLen; l++ {
					wi[j][k*f.Params.VecLen+l] = msk.w[k][l][i][j]
				}
			}
		}

		mctI := make([]data.VectorG1, f.Params.VecLen+4)
		mctI[0] = mct[0]
		mctI[1] = mct[1]
		mctI[f.Params.VecLen+2] = mct[f.Params.NumClients*f.Params.VecLen+2]
		mctI[f.Params.VecLen+3] = mct[f.Params.NumClients*f.Params.VecLen+3]
		for j := 0; j < f.Params.VecLen; j++ {
			mctI[2+j] = mct[i*f.Params.VecLen+j+2]
		}

		enckeys[i] = &NHQuadAdapEncKey{MgSK: mgenck[i], u: u[i], uT: uT[i], v: v[i], vT: vT[i], w: wi, MCTSingle: mctSingle, MDKSingle: mdkSingle, MCT: mctI, MDK: mdk}
	}

	return &msk, enckeys, pp, nil

}

// todo
func (f NHQuadAdap) Enc(ek *NHQuadAdapEncKey, i int, xhat data.Vector) (*NHQuadAdapCT, error) {
	//compute korenecker
	x := data.NewConstantVector(len(xhat)*len(xhat)+len(xhat)+1, big.NewInt(1))

	for i := 0; i < len(xhat); i++ {
		for j := 0; j < len(xhat); j++ {
			x[i*len(xhat)+j] = new(big.Int).Mul(xhat[i], xhat[j])
		}
		x[len(xhat)*len(xhat)+i] = xhat[i]
	}

	ict := make(data.MatrixG1, f.Params.VecLen)
	idk := make(data.MatrixG2, f.Params.VecLen)

	sampler := sample.NewUniform(bn256.Order)

	s, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	sT, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	r, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	t, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	gamma, err := data.NewRandomVector((4), sampler)

	for j := 0; j < f.Params.VecLen; j++ {

		//ictj = cj*MCT1 + s*MCT2+j + ruij*MCT2+m + vij*MCT3+m + sum(gamma*MCT0)
		ict[j] = ek.MCT[1].MulScalar(x[j]).Add(ek.MCT[2+f.Params.VecLen].MulScalar(new(big.Int).Mul(r, ek.u[j]))).Add(ek.MCT[3+f.Params.VecLen].MulScalar(ek.v[j]))

		ict[j] = ict[j].Add(ek.MCT[2+j].MulScalar(s))

		idk[j] = ek.MDK[1].MulScalar(x[j]).Add(ek.MDK[2+f.Params.VecLen*f.Params.NumClients].MulScalar(ek.uT[j])).Add(ek.MDK[3+f.Params.VecLen*f.Params.NumClients].MulScalar(new(big.Int).Mul(t, ek.vT[j])))
		// add w
		for k := 0; k < f.Params.NumClients*f.Params.VecLen; k++ {
			idk[j] = idk[j].Add(ek.MDK[2+k].MulScalar(new(big.Int).Mul(sT, ek.w[j][k])))
		}

		ict[j].Add(ek.MCT[0].MulScalar(gamma[0]))
		idk[j].Add(ek.MDK[0].MulScalar(gamma[1]))

	}

	icts := ek.MCTSingle[1].MulScalar(s)
	idks := ek.MDKSingle[1].MulScalar(sT)

	icts.Add(ek.MCT[0].MulScalar(gamma[2]))
	idks.Add(ek.MDK[0].MulScalar(gamma[3]))

	mgFE := fullysec.NewFHMGIPEFromParams(&fullysec.FHMGIPEParams{SecLevel: f.Params.SecLevel, NumClients: f.Params.NumClients, VecLenX1: f.Params.VecLen*f.Params.VecLen*f.Params.NumClients + 3, VecLenX2: 1,
		BoundX1: f.Params.BoundX, BoundX2: f.Params.BoundX, BoundY1: f.Params.BoundY, BoundY2: f.Params.BoundY})

	fmg := data.NewConstantVector(f.Params.NumClients*f.Params.VecLen*f.Params.VecLen+3, big.NewInt(0))

	fmg[0] = r
	fmg[1] = t
	fmg[2] = big.NewInt(-1)
	h := data.NewConstantVector(1, big.NewInt(0))

	mgct, err := mgFE.Encrypt(fmg, h, i, ek.MgSK)
	if err != nil {
		return nil, err
	}

	return &NHQuadAdapCT{ICT: ict, IDK: idk, ICTSingle: icts, IDKSingle: idks, MgCT: mgct}, nil

}

// DeriveKey takes a vector c who represents a quadratic function
// master secret key, and returns the functional encryption key. That is
// a key that for encrypted x_1, ..., y_n  allows to calculate the sum of
// c(ki,j,k,l)x_i[j]x_k[l].  In case the key could not
// be derived, it returns an error.
func (f NHQuadAdap) DeriveKey(c [][]data.Matrix, noise *big.Int, msk *NHQuadAdapSecKey) (*NHQuadAdapDK, error) {

	//check if c is correctly build, (for i >= k => cijkl = 0)
	for k := 0; k < f.Params.NumClients; k++ {
		for i := k; i < f.Params.NumClients; i++ {
			for j := 0; j < f.Params.VecLen; j++ {
				for l := 0; l < f.Params.VecLen; l++ {
					if c[i][j][k][l].Cmp(big.NewInt(0)) != 0 {
						return nil, errors.New("c has wrong form")
					}
				}
			}
		}
	}

	//sample noise values
	sampler := sample.NewUniform(bn256.Order)
	nu, err := data.NewRandomVector(f.Params.NumClients, sampler)
	if err != nil {
		return nil, err
	}

	ones := data.NewConstantVector(f.Params.NumClients-1, big.NewInt(1))
	//random vector generated from nu
	r := data.NewVector(nu[0:(f.Params.NumClients - 1)])
	//dotproduct of r and ones
	sum, err := r.Dot(ones)
	if err != nil {
		return nil, err
	}

	//compute modulus of sum, negate it add noise to it
	sum.Neg(sum).Mod(sum, bn256.Order)
	sum.Add(sum, noise)
	nu[f.Params.NumClients-1] = sum

	fT := make(data.Matrix, f.Params.NumClients)
	hT := data.NewConstantMatrix(f.Params.NumClients, 1, big.NewInt(0))
	for i := 0; i < f.Params.NumClients; i++ {
		fT[i] = data.NewConstantVector(3+f.Params.NumClients*f.Params.VecLen*f.Params.VecLen, big.NewInt(0))

		for j := 0; j < f.Params.VecLen; j++ {
			for k := 0; k < f.Params.NumClients; k++ {
				for l := 0; l < f.Params.VecLen; l++ {
					fT[i][0].Add(fT[i][0], new(big.Int).Mul(c[i][j][k][l].Mod(c[i][j][k][l], bn256.Order), new(big.Int).Mul(msk.u[i][j], msk.uT[k][l])))
					fT[i][1].Add(fT[i][1], new(big.Int).Mul(c[k][l][i][j].Mod(c[k][l][i][j], bn256.Order), new(big.Int).Mul(msk.v[k][l], msk.vT[i][j])))
				}
			}
		}
		fT[i][2] = nu[i]
	}

	mgFE := fullysec.NewFHMGIPEFromParams(&fullysec.FHMGIPEParams{SecLevel: f.Params.SecLevel, NumClients: f.Params.NumClients, VecLenX1: f.Params.VecLen*f.Params.VecLen*f.Params.NumClients + 3, VecLenX2: 1,
		BoundX1: f.Params.BoundX, BoundX2: f.Params.BoundX, BoundY1: f.Params.BoundY, BoundY2: f.Params.BoundY})

	mgdk, err := mgFE.DeriveKey(fT, hT, msk.MgMSK)
	if err != nil {
		return nil, err
	}

	sigma := data.NewConstantMatrix(f.Params.NumClients, f.Params.NumClients, big.NewInt(0))
	for i := 0; i < f.Params.NumClients; i++ {
		for k := 0; k < f.Params.NumClients; k++ {
			for j := 0; j < f.Params.VecLen; j++ {
				for l := 0; l < f.Params.VecLen; l++ {
					sigma[i][k].Add(sigma[i][k], new(big.Int).Mul(c[i][j][k][l], msk.w[i][j][k][l]))
				}
			}

		}
	}

	return &NHQuadAdapDK{C: c, MgDK: mgdk, Sigma: sigma}, nil
}

// Decrypt accepts the ciphertext as a encryption of vectors
// x_1,...,x_m and a functional encryption key corresponding to  a vector c.
// It returns the sum of c(ki,j,k,l)x_i[j]x_k[l].   If decryption
// failed, an error is returned.
func (f *NHQuadAdap) Decrypt(cipher []*NHQuadAdapCT, dk *NHQuadAdapDK, pubKey *bn256.GT) (*big.Int, error) {

	iFE1 := fullysec.NewFHTAO20FromParams(&fullysec.FHTAO20Params{SecLevel: f.Params.SecLevel, VecLen: f.Params.VecLen*f.Params.NumClients + 3*f.Params.VecLen + 4, BoundX: f.Params.BoundX, BoundY: f.Params.BoundY})

	iFE2 := fullysec.NewFHTAO20FromParams(&fullysec.FHTAO20Params{SecLevel: f.Params.SecLevel, VecLen: 2, BoundX: f.Params.BoundX, BoundY: f.Params.BoundY})

	mgFE := fullysec.NewFHMGIPEFromParams(&fullysec.FHMGIPEParams{SecLevel: f.Params.SecLevel, NumClients: f.Params.NumClients, VecLenX1: f.Params.VecLen*f.Params.VecLen*f.Params.NumClients + 3, VecLenX2: 1,
		BoundX1: f.Params.BoundX, BoundX2: f.Params.BoundX, BoundY1: f.Params.BoundY, BoundY2: f.Params.BoundY})

	z1 := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	z2 := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	ciphermg := make([]*fullysec.FHMGIPECT, f.Params.NumClients)

	for i := 0; i < f.Params.NumClients; i++ {
		ciphermg[i] = cipher[i].MgCT
		for k := 0; k < f.Params.NumClients; k++ {
			if dk.Sigma[i][k].Cmp(big.NewInt(0)) != 0 {
				z2.Add(z2, new(bn256.GT).ScalarMult(iFE2.DecryptWOSearch(cipher[i].ICTSingle, cipher[k].IDKSingle, pubKey), dk.Sigma[i][k]))
			}
			for j := 0; j < f.Params.VecLen; j++ {
				for l := 0; l < f.Params.VecLen; l++ {
					if dk.C[i][j][k][l].Cmp(big.NewInt(0)) != 0 {
						z1.Add(z1, new(bn256.GT).ScalarMult(iFE1.DecryptWOSearch(cipher[i].ICT[j], cipher[k].IDK[l], pubKey), dk.C[i][j][k][l]))
					}
				}
			}
		}
	}

	z3 := mgFE.DecryptWOS(ciphermg, dk.MgDK, pubKey)
	z := new(bn256.GT).ScalarBaseMult(big.NewInt(0))
	z.Add(z1, new(bn256.GT).Neg(z2))
	z.Add(z, new(bn256.GT).Neg(z3))

	b := f.Params.VecLen * f.Params.VecLen * f.Params.NumClients * f.Params.NumClients
	bound := new(big.Int).Mul(big.NewInt(int64(b)), new(big.Int).Mul(f.Params.BoundX, f.Params.BoundX))
	bound.Mul(bound, f.Params.BoundY)
	bound.Add(bound, f.Params.BoundNoise)

	dec, err := dlog.NewCalc().InBN256().WithNeg().WithBound(bound).BabyStepGiantStep(z, pubKey)

	return dec, err
}
