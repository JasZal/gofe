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

// Params represents configuration parameters for the NHQuad scheme instance.
// SecLevel (int): The parameter defines the security assumption of the scheme, k >= 2, MMDH_k assumption
// NumClients (int): The number of clients participating
// VecLenX (int): The length of vectors x that clients want to encrypt.
// BoundX (int): The value by which the coordinates of encrypted vectors x are bounded.
// Bound (int): The value by which the coordinates of inner product vectors y are bounded.
type NHQuadParams struct {
	SecLevel   int      //k
	NumClients int      //n
	VecLen     int      //m = m'^2 + m' + 1
	BoundX     *big.Int //X
	BoundY     *big.Int //C
	BoundNoise *big.Int //Delta
}

// NHQuad represents a Noise Hiding Quadratic Functional Encryption scheme
// It allows clients to encrypt vectors {x_1, ..., x_m} and derive a secret key
// based on an quadratic function, displayed as a vector c[(i,j,k,l)] and a distribution Delta, so that a decryptor can
// decrypt the sum of c[(i,j,k,l)]xi[j]xk[l] + noise where noise is sampled via the distribution Delta, without revealing
// intermediate results.
// The scheme is based on a mixed-group inner product functional encryption scheme (AGT: "Multi-Input Quadratic Functional Encryption from Pairings") and an
//iFE scheme (TAO20: "Efficient Inner Product Functional Encryption with Full-Hiding Security")

// This struct contains the shared choice for parameters on which the
// functionality of the scheme depend.
type NHQuad struct {
	Params *NHQuadParams
}

// NHQuadSecKey represents a master secret key in NHQuad scheme.
type NHQuadSecKey struct {
	IMSK1  *fullysec.FHTAO20SecKey
	IMSK2  *fullysec.FHTAO20SecKey
	MgMSK  *fullysec.FHMGIPESecKey
	MgEncK []*fullysec.FHMGIPEEncKey
	w      [][]data.Matrix
	u      data.Matrix
	uT     data.Matrix
	v      data.Matrix
	vT     data.Matrix
}

// NHQuadEncKey represents the encryption keys in NHQuad scheme
type NHQuadEncKey struct {
	//ek_i = ({MCT_0,i,j},{MCT_1,i,j})
	EncKey [][]*NHQuadCT
}

// NHQuadCT represents a ciphertext in NHQuad scheme.
type NHQuadCT struct {
	ICT       data.MatrixG1
	IDK       data.MatrixG2
	ICTSingle data.VectorG1
	IDKSingle data.VectorG2
	MgCT      *fullysec.FHMGIPECT
}

// NHQuadDK represents a decryption key in NHQuad scheme.
type NHQuadDK struct {
	C     [][]data.Matrix
	MgDK  *fullysec.FHMGIPEDK
	Sigma data.Matrix
}

// NewNHQuad configures a new instance of the scheme. See struct
// NHQuadParams for the description of the parameters. It returns
// a new NHQuad instance.
func NewNHQuad(secLevel, numClients, vecLen int, boundx, boundy, boundn *big.Int) *NHQuad {
	params := &NHQuadParams{SecLevel: secLevel, NumClients: numClients,
		VecLen: vecLen, BoundX: boundx, BoundY: boundy, BoundNoise: boundn}
	return &NHQuad{Params: params}
}

// NewNHQuadFromParams takes configuration parameters of an existing
// NHQuad scheme instance, and reconstructs the scheme with the same
// configuration parameters. It returns a new NHQuad instance.
func NewNHQuadFromParams(params *NHQuadParams) *NHQuad {
	return &NHQuad{
		Params: params,
	}
}

// GenerateKeys generates a triple of master secret key, encryption keys and a public key
// for the scheme. It returns an error in case keys could not be
// generated.
func (f NHQuad) GenerateKeys() (*NHQuadSecKey, []*NHQuadEncKey, *bn256.GT, error) {

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

	msk := NHQuadSecKey{IMSK1: imsk1, IMSK2: imsk2, MgMSK: mgmsk, MgEncK: mgenck, w: w, u: u, uT: uT, v: v, vT: vT}

	//ecnryption keys
	enckeys := make([]*NHQuadEncKey, f.Params.NumClients)

	//one hot vectors
	e := data.NewConstantMatrix(f.Params.VecLen, f.Params.VecLen, big.NewInt(0))
	for j := 0; j < f.Params.VecLen; j++ {
		e[j][j] = big.NewInt(1)
	}

	for i := 0; i < f.Params.NumClients; i++ {
		enckeys[i] = &NHQuadEncKey{EncKey: make([][]*NHQuadCT, 2)}

		////ek_i = ({MCT_0,i,j},{MCT_1,i,j})
		enckeys[i].EncKey[0] = make([]*NHQuadCT, 4*f.Params.VecLen+2*f.Params.SecLevel+17) //j in D
		enckeys[i].EncKey[1] = make([]*NHQuadCT, f.Params.VecLen)                          //j in m

		for j := 0; j < 4*f.Params.VecLen+2*f.Params.SecLevel+17; j++ {
			enckeys[i].EncKey[0][j], err = f.MstEnc(&msk, i, data.NewConstantVector(f.Params.VecLen, big.NewInt(0)))
			if err != nil {
				return nil, nil, nil, err
			}
			if j < f.Params.VecLen {
				enckeys[i].EncKey[1][j], err = f.MstEnc(&msk, i, e[j])
				if err != nil {
					return nil, nil, nil, err
				}
			}
		}
	}

	return &msk, enckeys, pp, nil

}

// todo
func (f NHQuad) MstEnc(msk *NHQuadSecKey, i int, x data.Vector) (*NHQuadCT, error) {

	ict := make(data.MatrixG1, f.Params.VecLen)
	idk := make(data.MatrixG2, f.Params.VecLen)

	iFE1 := fullysec.NewFHTAO20FromParams(&fullysec.FHTAO20Params{SecLevel: f.Params.SecLevel, VecLen: f.Params.VecLen*f.Params.NumClients + 3*f.Params.VecLen + 4, BoundX: f.Params.BoundX, BoundY: f.Params.BoundY})

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

	b := make(data.Matrix, f.Params.VecLen)
	bT := make(data.Matrix, f.Params.VecLen)

	for j := 0; j < f.Params.VecLen; j++ {
		b[j] = data.NewConstantVector(f.Params.NumClients*f.Params.VecLen+3*f.Params.VecLen+4, big.NewInt(0))
		bT[j] = data.NewConstantVector(f.Params.NumClients*f.Params.VecLen+3*f.Params.VecLen+4, big.NewInt(0))
		b[j][0] = x[j]
		bT[j][0] = x[j]

		//se_ij
		eij := data.NewConstantVector(f.Params.NumClients*f.Params.VecLen, big.NewInt(0))
		eij[i*f.Params.VecLen+j] = big.NewInt(1)
		se := eij.MulScalar(s)

		//sTwij
		wij := data.NewConstantVector(f.Params.NumClients*f.Params.VecLen, big.NewInt(0))
		for k := 0; k < f.Params.NumClients; k++ {
			for l := 0; l < f.Params.VecLen; l++ {
				wij[k*f.Params.VecLen+l] = msk.w[k][l][i][j]
			}
		}
		sTwij := wij.MulScalar(sT)

		for k := 0; k < f.Params.NumClients*f.Params.VecLen; k++ {
			b[j][2+k] = se[k]
			bT[j][2+k] = sTwij[k]
		}

		b[j][f.Params.NumClients*f.Params.VecLen+2] = big.NewInt(1).Mul(r, msk.u[i][j])
		b[j][f.Params.NumClients*f.Params.VecLen+3] = msk.v[i][j]

		bT[j][f.Params.NumClients*f.Params.VecLen+2] = msk.uT[i][j]
		bT[j][f.Params.NumClients*f.Params.VecLen+3] = big.NewInt(1).Mul(t, msk.vT[i][j])
		var err error
		ict[j], err = iFE1.Encrypt(b[j], msk.IMSK1.BHat)

		if err != nil {
			return nil, err
		}
		idk[j], err = iFE1.DeriveKey(bT[j], msk.IMSK1.BStarHat)
		if err != nil {
			return nil, err
		}

	}

	iFE2 := fullysec.NewFHTAO20FromParams(&fullysec.FHTAO20Params{SecLevel: f.Params.SecLevel, VecLen: 2, BoundX: f.Params.BoundX, BoundY: f.Params.BoundY})
	icts, err := iFE2.Encrypt(data.NewVector([]*big.Int{s, big.NewInt(0)}), msk.IMSK2.BHat)

	if err != nil {
		return nil, err
	}

	idks, err := iFE2.DeriveKey(data.NewVector([]*big.Int{sT, big.NewInt(0)}), msk.IMSK2.BStarHat)

	if err != nil {
		return nil, err
	}

	mgFE := fullysec.NewFHMGIPEFromParams(&fullysec.FHMGIPEParams{SecLevel: f.Params.SecLevel, NumClients: f.Params.NumClients, VecLenX1: f.Params.VecLen*f.Params.VecLen*f.Params.NumClients + 3, VecLenX2: 1,
		BoundX1: f.Params.BoundX, BoundX2: f.Params.BoundX, BoundY1: f.Params.BoundY, BoundY2: f.Params.BoundY})

	fmg := data.NewConstantVector(f.Params.NumClients*f.Params.VecLen*f.Params.VecLen+3, big.NewInt(0))

	fmg[0] = r
	fmg[1] = t
	fmg[2] = big.NewInt(-1)
	h := data.NewConstantVector(1, big.NewInt(0))

	mgct, err := mgFE.Encrypt(fmg, h, i, msk.MgEncK[i])
	if err != nil {
		return nil, err
	}
	return &NHQuadCT{ICT: ict, IDK: idk, ICTSingle: icts, IDKSingle: idks, MgCT: mgct}, nil
}

// Encrypt encrypts input vector (x_1) with the provided part of the master secret key.
// It returns a ciphertext vector . If encryption failed, error is returned.
func (f NHQuad) Encrypt(xhat data.Vector, i int, ek NHQuadEncKey) (*NHQuadCT, error) {

	x := data.NewConstantVector(len(xhat)*len(xhat)+len(xhat)+1, big.NewInt(1))
	//check if x has right size
	if len(x) != f.Params.VecLen {
		return nil, errors.New("error: xhat has wrong size")
	}

	//compute kroenecker product
	for i := 0; i < len(xhat); i++ {
		for j := 0; j < len(xhat); j++ {
			x[i*len(xhat)+j] = new(big.Int).Mul(xhat[i], xhat[j])
		}
		x[len(xhat)*len(xhat)+i] = xhat[i]
	}

	sampler := sample.NewUniform(bn256.Order)
	//D-1/2, D = 4m+2k+17
	gamma, err := data.NewRandomVector((2*f.Params.VecLen + f.Params.SecLevel + 8), sampler)

	if err != nil {
		return nil, err
	}

	ict := make(data.MatrixG1, f.Params.VecLen)
	idk := make(data.MatrixG2, f.Params.VecLen)
	var icts data.VectorG1
	var idks data.VectorG2
	mict := data.NewConstantVector(2*f.Params.NumClients*f.Params.VecLen*f.Params.VecLen+4*f.Params.SecLevel+11, big.NewInt(0)).MulG1()

	mgidk := data.NewConstantVector(4*f.Params.SecLevel+5, big.NewInt(0)).MulG2()

	mgct := &fullysec.FHMGIPECT{MiCT: mict, IDK: mgidk}

	for i := 0; i < f.Params.VecLen; i++ {
		ict[i] = ek.EncKey[0][1].ICT[i]
		idk[i] = ek.EncKey[0][1].IDK[i]
		if i == 0 {
			icts = ek.EncKey[0][1].ICTSingle
			idks = ek.EncKey[0][1].IDKSingle
			mgct.IDK = ek.EncKey[0][1].MgCT.IDK
			mgct.MiCT = ek.EncKey[0][1].MgCT.MiCT
		}

		for j := 0; j < f.Params.VecLen; j++ {
			ict[i] = ict[i].Add(ek.EncKey[1][j].ICT[i].MulScalar(x[j]).Add(ek.EncKey[0][0].ICT[i].MulScalar(new(big.Int).Mul(x[j], big.NewInt(-1)))))
			idk[i] = idk[i].Add(ek.EncKey[1][j].IDK[i].MulScalar(x[j]).Add(ek.EncKey[0][0].IDK[i].MulScalar(new(big.Int).Mul(x[j], big.NewInt(-1)))))
			if i == 0 {

				icts = icts.Add(ek.EncKey[1][j].ICTSingle.MulScalar(x[j]).Add(ek.EncKey[0][0].ICTSingle.MulScalar(new(big.Int).Mul(x[j], big.NewInt(-1)))))
				idks = idks.Add(ek.EncKey[1][j].IDKSingle.MulScalar(x[j]).Add(ek.EncKey[0][0].IDKSingle.MulScalar(new(big.Int).Mul(x[j], big.NewInt(-1)))))
				mgct.IDK = mgct.IDK.Add(ek.EncKey[1][j].MgCT.IDK.MulScalar(x[j]).Add(ek.EncKey[0][0].MgCT.IDK.MulScalar(new(big.Int).Mul(x[j], big.NewInt(-1)))))
				mgct.MiCT = mgct.MiCT.Add(ek.EncKey[1][j].MgCT.MiCT.MulScalar(x[j]).Add(ek.EncKey[0][0].MgCT.MiCT.MulScalar(new(big.Int).Mul(x[j], big.NewInt(-1)))))

			}
		}
		for j := 0; j < 2*f.Params.VecLen+f.Params.SecLevel+8; j++ { // (D-1)/2
			ict[i] = ict[i].Add(ek.EncKey[0][2*j].ICT[i].Add(ek.EncKey[0][2*j+1].ICT[i].Neg()).MulScalar(gamma[j]))
			idk[i] = idk[i].Add(ek.EncKey[0][2*j].IDK[i].Add(ek.EncKey[0][2*j+1].IDK[i].Neg()).MulScalar(gamma[j]))
			if i == 0 {
				icts = icts.Add(ek.EncKey[0][2*j].ICTSingle.Add(ek.EncKey[0][2*j+1].ICTSingle.Neg()).MulScalar(gamma[j]))
				idks = idks.Add(ek.EncKey[0][2*j].IDKSingle.Add(ek.EncKey[0][2*j+1].IDKSingle.Neg()).MulScalar(gamma[j]))
				mgct.IDK = mgct.IDK.Add(ek.EncKey[0][2*j].MgCT.IDK.Add(ek.EncKey[0][2*j+1].MgCT.IDK.Neg()).MulScalar(gamma[j]))
				mgct.MiCT = mgct.MiCT.Add(ek.EncKey[0][2*j].MgCT.MiCT.Add(ek.EncKey[0][2*j+1].MgCT.MiCT.Neg()).MulScalar(gamma[j]))
			}
		}
	}

	return &NHQuadCT{ICT: ict, IDK: idk, ICTSingle: icts, IDKSingle: idks, MgCT: mgct}, nil
}

// DeriveKey takes a vector c who represents a quadratic function
// master secret key, and returns the functional encryption key. That is
// a key that for encrypted x_1, ..., y_n  allows to calculate the sum of
// c(ki,j,k,l)x_i[j]x_k[l].  In case the key could not
// be derived, it returns an error.
func (f NHQuad) DeriveKey(c [][]data.Matrix, noise *big.Int, msk *NHQuadSecKey) (*NHQuadDK, error) {

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

	return &NHQuadDK{C: c, MgDK: mgdk, Sigma: sigma}, nil
}

// Decrypt accepts the ciphertext as a encryption of vectors
// x_1,...,x_m and a functional encryption key corresponding to  a vector c.
// It returns the sum of c(ki,j,k,l)x_i[j]x_k[l].   If decryption
// failed, an error is returned.
func (f *NHQuad) Decrypt(cipher []*NHQuadCT, dk *NHQuadDK, pubKey *bn256.GT) (*big.Int, error) {

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
