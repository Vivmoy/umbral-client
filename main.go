package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
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
	var inAPri, inBPub, inRKCondition, inN, inT, inBT *walk.TextEdit
	var outFileDes, inReFile *walk.TextEdit
	var inEncPub, inCondition, outE, outV, outS *walk.TextEdit
	var inE, inV, inS *walk.TextEdit
	var inDecAPri, inDecAPub, inDecBPri *walk.TextEdit
	var inAE, inAV, inAS, inAC *walk.TextEdit

	MainWindow{
		Title:    "umbral client",
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
				MaxSize: Size{Height: 30},
				Children: []Widget{
					TextEdit{AssignTo: &inReFile, ReadOnly: true, Text: "选择重加密文件"},
				},
			},
			PushButton{
				Text: "选择文件",
				OnClicked: func() {
					dlg := new(walk.FileDialog)
					dlg.Title = "选择文件"
					if ok, err := dlg.ShowOpen(mw); err != nil {
						inReFile.SetText(err.Error())
					} else if !ok {
						inReFile.SetText("未选择文件")
					} else {
						inReFile.SetText(dlg.FilePath)
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
					aPubKey, aPriKey, _ := curve.GenerateKeys()
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
					TextEdit{AssignTo: &inN, Text: "在这里输入总数值N..."},
					TextEdit{AssignTo: &inT, Text: "在这里输入门限值t..."},
					TextEdit{AssignTo: &inRKCondition, Text: "在这里输入重加密条件..."},
				},
			},
			PushButton{
				Text: "生成重加密密钥",
				OnClicked: func() {
					aPriKey := decodePrivateKey(inAPri.Text())
					bPubKey := decodePublicKey(inBPub.Text())
					N, _ := strconv.Atoi(inN.Text())
					t, _ := strconv.Atoi(inT.Text())
					strCondition := inRKCondition.Text()
					tmp, _ := strconv.ParseInt(strCondition, 10, 64)
					condition := big.NewInt(tmp)
					KF, _ := recrypt.ReKeyGen(aPriKey, bPubKey, N, t, condition)

					file, _ := os.Create("KF.json")
					defer file.Close()
					buf, _ := json.MarshalIndent(KF, "", "	")
					file.Write(buf)
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
					TextEdit{AssignTo: &inE, Text: "在这里输入CKA.E..."},
					TextEdit{AssignTo: &inV, Text: "在这里输入CKA.V..."},
					TextEdit{AssignTo: &inS, Text: "在这里输入CKA.S..."},
				},
			},
			// 为了方便本地测试，故保留
			PushButton{
				Text: "模拟重加密",
				OnClicked: func() {
					reFilePath := inReFile.Text()
					data, _ := os.ReadFile(reFilePath)
					KF := []recrypt.KFrag{}
					json.Unmarshal(data, &KF)

					// file, _ := os.Create("test.json")
					// defer file.Close()
					// buf, _ := json.MarshalIndent(KF, "", "	")
					// file.Write(buf)

					s := new(big.Int)
					s, sok := s.SetString(inS.Text(), 10)
					if !sok {
						outFileDes.SetText("s生成失败")
					}
					aCipherBefore := &recrypt.Cipher_before_re{
						Capsule: &recrypt.Capsule{
							E: decodePublicKey(inE.Text()),
							V: decodePublicKey(inV.Text()),
							S: s,
						},
					}
					CF, _ := recrypt.ReEncrypt(KF, aCipherBefore)

					file, _ := os.Create("CF.json")
					defer file.Close()
					buf, _ := json.MarshalIndent(CF, "", "	")
					file.Write(buf)
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
					TextEdit{AssignTo: &inDecBPri, Text: "在这里输入B的私钥..."},
					TextEdit{AssignTo: &inDecAPub, Text: "在这里输入A的公钥..."},
					TextEdit{AssignTo: &inBT, Text: "在这里输入门限值t..."},
				},
			},
			PushButton{
				Text: "B解密文件",
				OnClicked: func() {
					reFilePath := inReFile.Text()
					jsonData, _ := ioutil.ReadFile(reFilePath)

					var frag1Array []recrypt.Cfrag
					json.Unmarshal(jsonData, &frag1Array)

					var CF []recrypt.CFrag
					for _, frag1 := range frag1Array {
						tmp1 := new(big.Int)
						tmp2, _ := tmp1.SetString(frag1.T, 10)
						frag2 := recrypt.CFrag{
							E_1: decodePublicKey(frag1.E_1),
							V_1: decodePublicKey(frag1.V_1),
							Id:  decodePrivateKey(frag1.Id),
							X_A: decodePublicKey(frag1.X_A),
							T:   tmp2,
						}
						CF = append(CF, frag2)
					}

					bPriKey := decodePrivateKey(inDecBPri.Text())
					aPubKey := decodePublicKey(inDecAPub.Text())

					filePath := outFileDes.Text()
					suffix := path.Ext(filePath)
					fileName := strings.TrimSuffix(filePath, suffix)
					decFilePath := fileName + "_decrypt" + suffix

					t, _ := strconv.Atoi(inBT.Text())

					err := recrypt.DecryptFrags(aPubKey, bPriKey, CF, t, filePath, decFilePath)
					if err != nil {
						outFileDes.SetText("File Decrypt Error:" + err.Error())
					} else {
						outFileDes.SetText("File Decrypt Success!")
					}
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
