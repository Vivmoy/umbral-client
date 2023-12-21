package recrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"walk-client/curve"
	"walk-client/math"
	"walk-client/utils"
)

type Capsule struct {
	E *ecdsa.PublicKey
	V *ecdsa.PublicKey
	S *big.Int
	C *ecdsa.PublicKey
}

type Cipher_before_re struct {
	CipherText []byte
	Capsule    *Capsule
}

type Cipher_after_re struct {
	CF         []CFrag
	CipherText []byte
}

type KFrag struct {
	Id  *ecdsa.PrivateKey
	Rk  *big.Int
	X_A *ecdsa.PublicKey
	U_1 *ecdsa.PublicKey
	Z_1 *big.Int
	Z_2 *big.Int
	C   *ecdsa.PublicKey
	T   *big.Int
}

type CFrag struct {
	E_1 *ecdsa.PublicKey
	V_1 *ecdsa.PublicKey
	Id  *ecdsa.PrivateKey
	X_A *ecdsa.PublicKey
	T   *big.Int
}

type Cfrag struct {
	E_1 string `json:"E_1"`
	V_1 string `json:"V_1"`
	Id  string `json:"Id"`
	X_A string `json:"X_A"`
	T   string `json:"T"`
}

func Encapsulate(pubKey *ecdsa.PublicKey, condition *big.Int) (keyBytes []byte, capsule *Capsule, err error) {
	s := new(big.Int)
	// generate E,V key-pairs
	pubE, priE, err := curve.GenerateKeys()
	pubV, priV, err := curve.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}
	// get H2(E || V)
	h := utils.HashToCurve(
		utils.ConcatBytes(
			curve.PointToBytes(pubE),
			curve.PointToBytes(pubV)))
	// get s = v + e * H2(E || V)
	s = math.BigIntAdd(priV.D, math.BigIntMul(priE.D, h))
	// get (pk_A)^{e+v}
	point1 := curve.PointScalarMul(pubKey, math.BigIntAdd(priE.D, priV.D))
	point := curve.PointScalarMul(point1, condition)
	// generate aes key
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, nil, err
	}
	capsule = &Capsule{
		E: pubE,
		V: pubV,
		S: s,
		C: curve.BigIntMulBase(condition),
	}
	return keyBytes, capsule, nil
}

func Encrypt(pubKey *ecdsa.PublicKey, infileName string, encfileName string, condition *big.Int) (cipher *Cipher_before_re, err error) {
	keyBytes, capsule, err := Encapsulate(pubKey, condition)
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(keyBytes)
	// use aes gcm algorithm to encrypt
	// mark keyBytes[:12] as nonce
	err = OFBFileEncrypt(key[:32], keyBytes[:12], infileName, encfileName)
	if err != nil {
		return nil, err
	}
	cipher = &Cipher_before_re{
		//CipherText: cipherText,
		Capsule: capsule,
	}
	return cipher, nil
}

func ReKeyGen(aPriKey *ecdsa.PrivateKey, bPubKey *ecdsa.PublicKey, N int, t int, condition *big.Int) ([]KFrag, error) {
	if t < 2 {
		return nil, fmt.Errorf("%s", "t must bigger than 1")
	}
	X_A, x_A, err := curve.GenerateKeys()
	if err != nil {
		return nil, err
	}
	// get d = H3(X_A,pk_b,pk_b^(x_A))
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(X_A),
				curve.PointToBytes(bPubKey)),
			curve.PointToBytes(curve.PointScalarMul(bPubKey, x_A.D))))
	coefficients, err := utils.GetCoefficients(aPriKey.D, d, t)
	//fmt.Println("coefficients:", coefficients)
	if err != nil {
		return nil, err
	}
	// get D = H6(pk_a,pk_b,pk_b^a)
	D := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(&aPriKey.PublicKey),
				curve.PointToBytes(bPubKey)),
			curve.PointToBytes(curve.PointScalarMul(bPubKey, aPriKey.D))))
	KF := []KFrag{}
	for i := 0; i < N; i++ {
		Y, y, err := curve.GenerateKeys()
		if err != nil {
			return nil, err
		}
		id, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		// get s_x = H5(id,D)
		s_x := utils.HashToCurve(
			utils.ConcatBytes(
				id.D.Bytes(),
				D.Bytes()))
		rk := utils.GetPolynomialValue(coefficients, s_x)
		U_1 := curve.BigIntMulBase(rk)
		// get z_1 = H4(Y,id,pk_a,pk_b,U_1,X_A)
		z_1 := utils.HashToCurve(
			utils.ConcatBytes(
				utils.ConcatBytes(
					utils.ConcatBytes(
						utils.ConcatBytes(
							utils.ConcatBytes(
								curve.PointToBytes(Y),
								id.D.Bytes()),
							curve.PointToBytes(&aPriKey.PublicKey)),
						curve.PointToBytes(bPubKey)),
					curve.PointToBytes(U_1)),
				curve.PointToBytes(X_A)))
		// get z_2 = y - a × z_1
		z_2 := math.BigIntSub(y.D, math.BigIntMul(aPriKey.D, z_1))
		kFrag := KFrag{
			Id:  id,
			Rk:  rk,
			X_A: X_A,
			U_1: U_1,
			Z_1: z_1,
			Z_2: z_2,
			C:   curve.BigIntMulBase(condition),
			T:   math.BigIntMul(condition, math.GetInvert(utils.HashToCurve(curve.PointToBytes(curve.BigIntMulBase(big.NewInt(int64(t))))))),
		}
		KF = append(KF, kFrag)
	}
	// KF长度为N
	return KF, nil
}

func ReEncapsulate(kFrag KFrag, capsule *Capsule) (*CFrag, error) {
	// if !kFrag.C.Equal(capsule.C) {
	// 	return nil, fmt.Errorf("%s", "condition not match")
	// }
	cFrag := CFrag{
		E_1: curve.PointScalarMul(capsule.E, kFrag.Rk),
		V_1: curve.PointScalarMul(capsule.V, kFrag.Rk),
		Id:  kFrag.Id,
		X_A: kFrag.X_A,
		T:   kFrag.T,
	}
	return &cFrag, nil
}

func ReEncrypt(KF []KFrag, cipher *Cipher_before_re) ([]CFrag, error) {
	CF := []CFrag{}
	l := len(KF)
	for i := 0; i < l; i++ {
		cFrag, err := ReEncapsulate(KF[i], cipher.Capsule)
		if err != nil {
			return nil, err
		}
		CF = append(CF, *cFrag)
	}
	// re_cipher中CF长度为KF的长度，即默认为N
	return CF, nil
}

func Decapsulate(aPriKey *ecdsa.PrivateKey, capsule *Capsule, condition *big.Int) (keyBytes []byte, err error) {
	point1 := curve.PointScalarAdd(capsule.E, capsule.V)
	point2 := curve.PointScalarMul(point1, aPriKey.D)
	point := curve.PointScalarMul(point2, condition)
	// generate aes key
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

func Decrypt(aPriKey *ecdsa.PrivateKey, cipher *Cipher_before_re, encfileName string, decfileName string, condition *big.Int) (err error) {
	keyBytes, err := Decapsulate(aPriKey, cipher.Capsule, condition)
	if err != nil {
		return err
	}
	key := hex.EncodeToString(keyBytes)
	// use aes gcm algorithm to encrypt
	// mark keyBytes[:12] as nonce
	err = OFBFileDecrypt(key[:32], keyBytes[:12], encfileName, decfileName)
	return err
}

func DecapsulateFrags(bPriKey *ecdsa.PrivateKey, aPubKey *ecdsa.PublicKey, CF []CFrag, t int) ([]byte, error) {
	// get D = H6(pk_a,pk_b,pk_a^b)
	D := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(aPubKey),
				curve.PointToBytes(&bPriKey.PublicKey)),
			curve.PointToBytes(curve.PointScalarMul(aPubKey, bPriKey.D))))

	// 此处假设传入的CF切片长度为t
	//t := len(CF)

	s_x := []*big.Int{}
	for i := 0; i < t; i++ {
		s_x_i := utils.HashToCurve(
			utils.ConcatBytes(
				CF[i].Id.D.Bytes(),
				D.Bytes()))
		s_x = append(s_x, s_x_i)
	}

	lamda_S := []*big.Int{}
	for i := 1; i <= t; i++ {
		lamda_i_S := big.NewInt(1)
		for j := 1; j <= t; j++ {
			if j == i {
				continue
			} else {
				lamda_i_S = math.BigIntMul(lamda_i_S, (math.BigIntMul(s_x[j-1], math.GetInvert(math.BigIntSub(s_x[j-1], s_x[i-1])))))
			}
		}
		lamda_S = append(lamda_S, lamda_i_S)
	}

	E := curve.PointScalarMul(CF[0].E_1, lamda_S[0])
	V := curve.PointScalarMul(CF[0].V_1, lamda_S[0])

	for i := 1; i < t; i++ {
		E = curve.PointScalarAdd(E, curve.PointScalarMul(CF[i].E_1, lamda_S[i]))
		V = curve.PointScalarAdd(V, curve.PointScalarMul(CF[i].V_1, lamda_S[i]))
	}

	// get d = H3(X_A,pk_b,X_A^b)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(CF[0].X_A),
				curve.PointToBytes(&bPriKey.PublicKey)),
			curve.PointToBytes(curve.PointScalarMul(CF[0].X_A, bPriKey.D))))

	condition := math.BigIntMul(CF[0].T, utils.HashToCurve(curve.PointToBytes(curve.BigIntMulBase(big.NewInt(int64(t))))))
	point1 := curve.PointScalarMul(curve.PointScalarAdd(E, V), d)
	point := curve.PointScalarMul(point1, condition)
	keyBytes, err := utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

func DecryptFrags(aPubKey *ecdsa.PublicKey, bPriKey *ecdsa.PrivateKey, CF []CFrag, t int, encfileName string, decfileName string) (err error) {
	// 此处假设传入的CF切片长度为默认的N
	// cf := []CFrag{}
	// for i := 0; i < t; i++ {
	// 	cf = append(cf, CF[i])
	// }

	// cf = append(cf, CF[1])
	// cf = append(cf, CF[9])
	// cf = append(cf, CF[5])
	// cf = append(cf, CF[8])
	// cf = append(cf, CF[0])

	keyBytes, err := DecapsulateFrags(bPriKey, aPubKey, CF, t)
	if err != nil {
		return err
	}
	key := hex.EncodeToString(keyBytes)
	err = OFBFileDecrypt(key[:32], keyBytes[:12], encfileName, decfileName)
	return err
}
