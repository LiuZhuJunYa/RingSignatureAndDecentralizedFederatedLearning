package RingSignature

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

// CreateSigner 创建签名者信息
func CreateSigner(Signer_S Signer, Msg Message) Signer {
	r_s, err := crypto.GenerateKey() // 选中一个随机数 r_s 属于 Zq*
	if err != nil {
		fmt.Println("生成 r_s 随机数失败......")
	}
	Signer_S.R_S = r_s.PublicKey
	Signer_S.C_S = HashToZq(DotProduct(Signer_S.SK_S, Signer_S.PK_S), r_s.PublicKey)
	Signer_S.S_S = ComputeS_S(*r_s, HashToZq(DotProduct(Signer_S.SK_S, Signer_S.PK_S), r_s.PublicKey), Msg.SK_M)

	return Signer_S
}

// ComputeS_S 计算 S_S = (r_s - C_S * sk_M) mod q
func ComputeS_S(R_S, C_S, SK_M ecdsa.PrivateKey) ecdsa.PrivateKey {
	curve := crypto.S256()         // secp256k1 曲线
	curveOrder := curve.Params().N // 曲线阶 q

	// 提取私钥值
	r_s_Value := R_S.D
	c_s_Value := C_S.D
	sk_M_Value := SK_M.D

	// 检查输入值是否为 nil
	if r_s_Value == nil {
		panic("r_s_Value: input private key values cannot be nil")
	}
	if c_s_Value == nil {
		panic("c_s_Value: input private key values cannot be nil")
	}
	if sk_M_Value == nil {
		panic("sk_M_Value: input private key values cannot be nil")
	}

	// 计算 S_S = (r_s - C_S * sk_M) mod q
	product := new(big.Int).Mul(c_s_Value, sk_M_Value) // C_S * sk_M
	result := new(big.Int).Sub(r_s_Value, product)     // r_s - (C_S * sk_M)
	result.Mod(result, curveOrder)                     // 结果取模 q 确保在有限域内

	// 将结果封装为新的 *ecdsa.PrivateKey
	S_S := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     nil,
			Y:     nil,
		},
		D: result,
	}
	S_S.PublicKey.X, S_S.PublicKey.Y = curve.ScalarBaseMult(result.Bytes())
	return S_S
}

// CreateMessage 创建签名信息类型
func CreateMessage(MessageText string) Message {
	SK_M, err := crypto.GenerateKey() // 选中一个随机数 SK_M 属于 Zq*
	if err != nil {
		fmt.Println("生成针对消息的随机数密钥失败......")
	}

	return Message{
		Text: []byte(MessageText),
		SK_M: *SK_M,
		PK_M: SK_M.PublicKey,
	}
}

// DotProduct 实现椭圆曲线点的标量乘法
func DotProduct(privateKey ecdsa.PrivateKey, publicKey ecdsa.PublicKey) ecdsa.PublicKey {
	// 获取 secp256k1 曲线
	curve := crypto.S256()

	// 提取私钥值 d 和公钥点 (X, Y)
	d := privateKey.D
	pubX := publicKey.X
	pubY := publicKey.Y

	// 使用椭圆曲线的标量乘法公式：result = d * (pubX, pubY)
	newX, newY := curve.ScalarMult(pubX, pubY, d.Bytes())

	// 将结果装载为 *ecdsa.PublicKey 并返回
	result := ecdsa.PublicKey{
		Curve: curve,
		X:     newX,
		Y:     newY,
	}
	return result
}

// HashToZq 将输入参数处理成 SHA256 哈希并映射到以太坊私钥
func HashToZq(args ...interface{}) ecdsa.PrivateKey {
	curve := crypto.S256()         // secp256k1 曲线
	curveOrder := curve.Params().N // 曲线阶 q

	// 拼接所有参数为字节数组
	var concatenated []byte

	for _, arg := range args {
		switch v := arg.(type) {
		case []byte:
			// 如果是 []byte，直接拼接
			concatenated = append(concatenated, v...)
		case ecdsa.PublicKey:
			// 如果是 ecdsa.PublicKey，拼接 X 和 Y
			concatenated = append(concatenated, v.X.Bytes()...)
			concatenated = append(concatenated, v.Y.Bytes()...)
		case []ecdsa.PublicKey:
			// 如果是 []ecdsa.PublicKey，遍历拼接每个公钥的 X 和 Y
			for _, pubKey := range v {
				concatenated = append(concatenated, pubKey.X.Bytes()...)
				concatenated = append(concatenated, pubKey.Y.Bytes()...)
			}
		case ecdsa.PrivateKey:
			// 如果是 ecdsa.PrivateKey，拼接 D
			concatenated = append(concatenated, v.D.Bytes()...)
		case []ecdsa.PrivateKey:
			// 如果是 []ecdsa.PrivateKey，遍历拼接每个私钥的 D
			for _, privKey := range v {
				concatenated = append(concatenated, privKey.D.Bytes()...)
			}
		default:
			// 如果是其他类型，抛出异常
			panic(fmt.Sprintf("不支持的哈希类型: %T", v))
		}
	}

	// 计算 SHA256 哈希
	hash := sha256.Sum256(concatenated)

	// 将哈希值映射到 secp256k1 的有限域内
	d := new(big.Int).SetBytes(hash[:])
	d.Mod(d, curveOrder) // 映射到曲线阶 q 内

	// 特殊情况：如果 d == 0，则设为 1（避免生成无效私钥）
	if d.Sign() == 0 {
		d.SetInt64(1)
	}

	// 使用生成的 d 创建私钥
	privateKey := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     nil,
			Y:     nil,
		},
		D: d,
	}
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	return privateKey
}
