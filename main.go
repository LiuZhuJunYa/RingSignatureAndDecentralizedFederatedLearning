package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"strings"
)

const (
	Puk_0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	Sk_0  = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)

func main() {
	// 打印钱包地址信息
	fmt.Println("钱包地址信息：", Puk_0)

	// 解析私钥
	privKeyHex := strings.TrimSpace(Sk_0)
	// 将私钥从16进制字符串转换为字节数组
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		fmt.Println("私钥格式错误：", err)
		return
	}
	privKey, err := crypto.ToECDSA(privKeyBytes)
	fmt.Println("钱包私钥信息", Sk_0)
	if err != nil {
		fmt.Println("无法解析私钥：", err)
		return
	}
	// 从私钥派生公钥
	pubKey := privKey.PublicKey
	fmt.Println("公钥（未压缩，十六进制）：", hex.EncodeToString(crypto.FromECDSAPub(&pubKey)))
	// 计算以太坊地址
	address := crypto.PubkeyToAddress(pubKey)
	fmt.Println("以太坊地址：", address.Hex())

	// 将公钥和私钥转换为ECIES密钥
	eciesPubKey := ecies.ImportECDSAPublic(&pubKey)
	eciesPrivKey := ecies.ImportECDSA(privKey)

	// 要加密的信息
	message := []byte("hello")

	// 使用公钥加密
	ciphertext, err := ecies.Encrypt(rand.Reader, eciesPubKey, message, nil, nil)
	if err != nil {
		fmt.Println("加密失败：", err)
		return
	}
	fmt.Println("加密后的信息：", hex.EncodeToString(ciphertext))

	// 使用私钥解密
	plaintext, err := eciesPrivKey.Decrypt(ciphertext, nil, nil)
	if err != nil {
		fmt.Println("解密失败：", err)
		return
	}
	fmt.Println("解密后的信息：", string(plaintext))
}
