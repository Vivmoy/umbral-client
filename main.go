package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"path"
	"strconv"
	"strings"
	"walk-client/curve"
	"walk-client/recrypt"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func main() {
	// walk部分---------------------------------------------------------------------------------------
	var mw *walk.MainWindow
	var outPri, outPub *walk.TextEdit
	var inAPri, inBPub, outRk, outPubX *walk.TextEdit
	var outFileDes *walk.TextEdit
	var inEncPub, inCondition, outE, outV, outS *walk.TextEdit
	var inRK, inE, inV, inS, outNewE, outNewV, outNewS *walk.TextEdit
	var capsule *recrypt.Capsule
	var inDecAPri, inDecBPri *walk.TextEdit
	var inAE, inAV, inAS, inAC *walk.TextEdit

	MainWindow{
		Title:    "qogry-client",
		Size:     Size{Width: 1200, Height: 750},
		AssignTo: &mw,
		Layout:   VBox{},
		Children: []Widget{
			HSplitter{
				MaxSize: Size{Height: 30},
				Children: []Widget{
					TextEdit{AssignTo: &outFileDes, ReadOnly: true, Text: "未选择文件"},
				},
			},
			PushButton{
				Text: "选择文件",
				OnClicked: func() {
					dlg := new(walk.FileDialog)
					dlg.Title = "选择文件"
					if ok, err := dlg.ShowOpen(mw); err != nil {
						outFileDes.SetText(err.Error())
					} else if !ok {
						outFileDes.SetText("未选择文件")
					} else {
						outFileDes.SetText(dlg.FilePath)
					}
				},
			},
			HSplitter{
				Children: []Widget{
					TextEdit{AssignTo: &outPri, ReadOnly: true, Text: "生成的私钥"},
					TextEdit{AssignTo: &outPub, ReadOnly: true, Text: "生成的公钥"},
				},
			},
			PushButton{
				Text: "生成密钥对",
				OnClicked: func() {
					aPriKey, aPubKey, _ := curve.GenerateKeys()
					pri := encodePrivateKey(aPriKey)
					pub := encodePublicKey(aPubKey)
					// outPri.SetText(strings.ToUpper("inTE.Text()"))
					outPri.SetText(pri)
					outPub.SetText(pub)
				},
			},
			HSplitter{
				Children: []Widget{
					TextEdit{AssignTo: &inAPri, Text: "在这里输入自己的私钥..."},
					TextEdit{AssignTo: &inBPub, Text: "在这里输入对方的公钥..."},
					TextEdit{AssignTo: &outRk, ReadOnly: true, Text: "生成的重加密密钥"},
					TextEdit{AssignTo: &outPubX, ReadOnly: true, Text: "生成的中间密钥参数"},
				},
			},
			PushButton{
				Text: "生成重加密密钥",
				OnClicked: func() {
					aPriKey := decodePrivateKey(inAPri.Text())
					bPubKey := decodePublicKey(inBPub.Text())
					rk, pubX, err := recrypt.ReKeyGen(aPriKey, bPubKey)
					if err != nil {
						fmt.Println(err)
					}
					outRk.SetText(rk.String())
					outPubX.SetText(encodePublicKey(pubX))
				},
			},
			HSplitter{
				Children: []Widget{
					TextEdit{AssignTo: &inEncPub, Text: "在这里输入加密者公钥..."},
					TextEdit{AssignTo: &inCondition, Text: "在这里输入加密条件..."},
					// 为了方便本地测试，故保留
					TextEdit{AssignTo: &outE, ReadOnly: true, Text: "生成的CKA.E信息"},
					TextEdit{AssignTo: &outV, ReadOnly: true, Text: "生成的CKA.V信息"},
					TextEdit{AssignTo: &outS, ReadOnly: true, Text: "生成的CKA.S信息"},
				},
			},
			PushButton{
				Text: "加密文件",
				OnClicked: func() {
					filePath := outFileDes.Text()
					suffix := path.Ext(filePath)
					fileName := strings.TrimSuffix(filePath, suffix)
					encFilePath := fileName + "_encrypt" + suffix
					//plain := fileToString(filePath)
					encPub := decodePublicKey(inEncPub.Text())
					strCondition := inCondition.Text()
					tmp, _ := strconv.ParseInt(strCondition, 10, 64)
					condition := big.NewInt(tmp)
					cipher_before, err := recrypt.Encrypt(encPub, filePath, encFilePath, condition)

					// 为了方便本地测试，故保留
					if err != nil {
						outFileDes.SetText("File Encrypt Error:" + err.Error())
					} else {
						outFileDes.SetText("File Encrypt Success!")
						outE.SetText(encodePublicKey(cipher_before.Capsule.E))
						outV.SetText(encodePublicKey(cipher_before.Capsule.V))
						outS.SetText(cipher_before.Capsule.S.String())
					}
				},
			},
			HSplitter{
				Children: []Widget{
					TextEdit{AssignTo: &inRK, Text: "在这里输入重加密密钥..."},
					TextEdit{AssignTo: &inE, Text: "在这里输入CKA.E..."},
					TextEdit{AssignTo: &inV, Text: "在这里输入CKA.V..."},
					TextEdit{AssignTo: &inS, Text: "在这里输入CKA.S..."},
					TextEdit{AssignTo: &outNewE, ReadOnly: true, Text: "生成的CKB.E信息"},
					TextEdit{AssignTo: &outNewV, ReadOnly: true, Text: "生成的CKB.V信息"},
					TextEdit{AssignTo: &outNewS, ReadOnly: true, Text: "生成的CKB.S信息"},
				},
			},
			// 为了方便本地测试，故保留
			PushButton{
				Text: "模拟重加密",
				OnClicked: func() {
					rk := new(big.Int)
					rk, rok := rk.SetString(inRK.Text(), 10)
					if !rok {
						outFileDes.SetText("rk生成失败")
					}
					s := new(big.Int)
					s, sok := s.SetString(inS.Text(), 10)
					if !sok {
						outFileDes.SetText("s生成失败")
					}
					capsule = &recrypt.Capsule{
						E: decodePublicKey(inE.Text()),
						V: decodePublicKey(inV.Text()),
						S: s,
					}
					newCapsule, err := recrypt.ReEncryption(rk, capsule)
					if err != nil {
						outFileDes.SetText("重加密失败:" + err.Error())
					} else {
						outFileDes.SetText("重加密成功")
						outNewE.SetText(encodePublicKey(newCapsule.E))
						outNewV.SetText(encodePublicKey(newCapsule.V))
						outNewS.SetText(newCapsule.S.String())
					}
				},
			},
			HSplitter{
				Children: []Widget{
					TextEdit{AssignTo: &inDecAPri, Text: "在这里输入解密私钥..."},
					TextEdit{AssignTo: &inAE, Text: "在这里输入CKA.E..."},
					TextEdit{AssignTo: &inAV, Text: "在这里输入CKA.V..."},
					TextEdit{AssignTo: &inAS, Text: "在这里输入CKA.S..."},
					TextEdit{AssignTo: &inAC, Text: "在这里输入解密条件..."},
				},
			},
			PushButton{
				Text: "A解密文件",
				OnClicked: func() {
					filePath := outFileDes.Text()

					aPriKey := decodePrivateKey(inDecAPri.Text())
					s := new(big.Int)
					s, sok := s.SetString(inAS.Text(), 10)
					if !sok {
						outFileDes.SetText("s生成失败")
					}
					aCipherBefore := &recrypt.Cipher_before_re{
						Capsule: &recrypt.Capsule{
							E: decodePublicKey(inAE.Text()),
							V: decodePublicKey(inAV.Text()),
							S: s,
						},
					}

					suffix := path.Ext(filePath)
					fileName := strings.TrimSuffix(filePath, suffix)
					decFilePath := fileName + "_self_decrypt" + suffix
					strCondition := inAC.Text()
					tmp, _ := strconv.ParseInt(strCondition, 10, 64)
					condition := big.NewInt(tmp)

					err := recrypt.Decrypt(aPriKey, aCipherBefore, filePath, decFilePath, condition)
					if err != nil {
						outFileDes.SetText("File Decrypt Error:" + err.Error())
					} else {
						outFileDes.SetText("File Decrypt Success!")
					}
				},
			},
			HSplitter{
				Children: []Widget{
					TextEdit{AssignTo: &inDecBPri, Text: "在这里输入解密私钥..."},
				},
			},
			PushButton{
				Text: "B解密文件",
				OnClicked: func() {
					// filePath := outFileDes.Text()
					// JsonParse := utils.NewJsonStruct()
					// v := form.ReEncryptCases{}
					// JsonParse.Load(filePath, &v)

					// bPriKey := decodePrivateKey(inDecBPri.Text())
					// ns := new(big.Int)
					// ns, sok := ns.SetString(v.NewCapsuleS, 10)
					// if !sok {
					// 	outFileDes.SetText("newS生成失败")
					// }
					// newCapsule = &recrypt.Capsule{
					// 	E: decodePublicKey(v.NewCapsuleE),
					// 	V: decodePublicKey(v.NewCapsuleV),
					// 	S: ns,
					// }
					// pubX := decodePublicKey(v.PubX)

					// suffix := v.File_Type
					// fileName := strings.TrimSuffix(filePath, suffix)
					// decFilePath := fileName + "_decrypt" + suffix

					// plain, err := recrypt.Decrypt(bPriKey, newCapsule, pubX, v.Cipher)
					// if err != nil {
					// 	outFileDes.SetText("File Decrypt Error:" + err.Error())
					// } else {
					// 	outFileDes.SetText("File Decrypt Success!")
					// }

					// file, _ := os.Create(decFilePath)
					// defer file.Close()
					// file.Write(plain)
				},
			},
		},
	}.Run()
}

// 实际调用的函数---------------------------------------------------------------------------------

// 工具函数-----------------------------------------------------------------------------
func encodePrivateKey(privateKey *ecdsa.PrivateKey) string {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return string(pemEncoded)
}

func encodePublicKey(publicKey *ecdsa.PublicKey) string {
	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	return string(pemEncodedPub)
}

func decodePrivateKey(pemEncoded string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)
	return privateKey
}
func decodePublicKey(pemEncodedPub string) *ecdsa.PublicKey {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)
	return publicKey
}

func fileToString(path string) string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(err.Error())
	}
	return string(data)
}
