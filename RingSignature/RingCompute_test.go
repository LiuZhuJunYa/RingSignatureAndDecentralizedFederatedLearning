package RingSignature

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
	"testing"
)

func TestSign(t *testing.T) {
	sk, _ := StringToPrivateKey("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	signer := Signer{
		SK_S: *sk,
		PK_S: sk.PublicKey,
		R_S:  ecdsa.PublicKey{},
		C_S:  ecdsa.PrivateKey{},
		S_S:  ecdsa.PrivateKey{},
	}
	var test []ecdsa.PublicKey
	Sign("Hello World", signer, test)
}

func TestCreateSigner(t *testing.T) {
	sk, _ := StringToPrivateKey("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	signer := Signer{
		SK_S: *sk,
		PK_S: sk.PublicKey,
		R_S:  ecdsa.PublicKey{},
		C_S:  ecdsa.PrivateKey{},
		S_S:  ecdsa.PrivateKey{},
	}
	signer_pi := CreateSigner(signer, CreateMessage("Hello World"))
	fmt.Println("SK_S: ", signer_pi.SK_S)
	fmt.Println("PK_S: ", signer_pi.PK_S)
	fmt.Println("R_S:  ", signer_pi.R_S)
	fmt.Println("C_S:  ", signer_pi.C_S)
	fmt.Println("S_S:  ", signer_pi.S_S)
}

func TestCreateMessage(t *testing.T) {
	msg := "hello world"
	MSG := CreateMessage(msg)
	fmt.Println(MSG)
}

func TestCompute(t *testing.T) {
	// 私钥字符串列表
	privateKeysHex := []string{
		"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
		"5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
		"7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
		"47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
	}

	// 初始化公钥列表
	var publicKeys []ecdsa.PublicKey

	for i, hexKey := range privateKeysHex {
		// 将私钥字符串转换为 *ecdsa.PrivateKey
		privateKey, err := StringToPrivateKey(hexKey)
		if err != nil {
			log.Fatalf("生成密钥失败 %d: %v", i, err)
		}

		// 提取公钥并加入公钥列表
		publicKeys = append(publicKeys, privateKey.PublicKey)
	}

	for i, publicKey := range publicKeys {
		fmt.Println("第", i, "个公钥信息是", publicKey)
	}
	fmt.Println("哈希的结果是：", HashToZq(publicKeys))
}

// StringToPrivateKey 将私钥字符串转换为 *ecdsa.PrivateKey
func StringToPrivateKey(hexKey string) (*ecdsa.PrivateKey, error) {
	// 将私钥字符串解码为字节
	privateKeyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("解析字符串密钥失败: %v", err)
	}
	// 使用以太坊库解析字节为私钥
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("通过字符串生成密钥失败: %v", err)
	}
	return privateKey, nil
}
