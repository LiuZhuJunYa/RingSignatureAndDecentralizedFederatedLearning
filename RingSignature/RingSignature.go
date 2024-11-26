package RingSignature

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"sync"
)

// 在实现签名时需要五种类型：消息、签名者、环成员列表、为环成员选择的随机点集、签名信息结果

// Message 第一种类型：消息类型
type Message struct {
	Text []byte            // 消息字符串，明文信息
	SK_M *ecdsa.PrivateKey // 为了对当前消息签名，而专门选择的一个随机数密钥
	PK_M *ecdsa.PublicKey  // 根据私钥生成的专门针对当前消息的公钥
}

// Signer 第二种类型：签名者类型
type Signer struct {
	SK_S *ecdsa.PrivateKey // 签名者的 ECC 私钥
	PK_S *ecdsa.PublicKey  // 签名者的 ECC 公钥
	R_S  *ecdsa.PublicKey  // 签名者自己计算得到的参数 R_S
	C_S  *ecdsa.PrivateKey // 签名者自己计算得到的参数 C_S
	S_S  *ecdsa.PrivateKey // 签名者自己计算得到的参数 S_S
}

//// RingList 第三种类型：环成员列表（在当前实验中我们选择是 5 位成员成环）
//type RingList struct {
//	// 签名时，签名顺序与签名者排位无关
//	PK_0 *ecdsa.PublicKey // 第一位成员
//	PK_1 *ecdsa.PublicKey // 第二位成员
//	PK_2 *ecdsa.PublicKey // 第三位成员
//	PK_3 *ecdsa.PublicKey // 第四位成员
//	PK_4 *ecdsa.PublicKey // 第五位成员
//}

//// RandomPoint 第四种类型：为环成员选择的随机点集
//type RandomPoint struct {
//	U_0 *ecdsa.PublicKey // 第一位成员选择的随机点
//	U_1 *ecdsa.PublicKey // 第二位成员选择的随机点
//	U_2 *ecdsa.PublicKey // 第三位成员选择的随机点
//	U_3 *ecdsa.PublicKey // 第四位成员选择的随机点
//	U_4 *ecdsa.PublicKey // 第五位成员选择的随机点
//}

// Result 第五种类型：签名信息结果
type Result struct {
	MessageText []byte             // 消息字符串，明文信息
	PK_M        *ecdsa.PublicKey   // 当前签名消息的主公钥
	List        []*ecdsa.PublicKey // 环成员公钥信息
	RandomPoint []*ecdsa.PublicKey // 为环成员选择的随机点集
	V           *ecdsa.PrivateKey  // 公开的参数V，有限域q内的正整数
	C           *ecdsa.PrivateKey  // 公开的参数C，有限域q内的正整数
	T           *ecdsa.PublicKey   // 公开的参数T，通过选择随机数t，计算得到的ECC上的点
	Pi          *ecdsa.PrivateKey  // 公开的参数Pi，有限域q内的正整数
}

// Sign 环签名函数
func Sign(message string, signer *Signer, list []*ecdsa.PublicKey) (sign_result Result, err error) {
	/* 创建消息类型 */
	var msg Message
	msg.Text = []byte(message)
	// 生成以太坊私钥
	sk_m, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println("生成针对消息的随机数密钥失败......")
	}
	// 生成公钥
	pk_m := sk_m.PublicKey
	msg.SK_M = sk_m
	msg.PK_M = &pk_m
	sign_result.MessageText = []byte(message)
	sign_result.PK_M = &pk_m

	/* 开始计算签名者中间参数信息 */
	r_s, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println("生成 r_s 随机数失败......")
	}
	if r_s.D == sk_m.D {
		fmt.Println("生成 r_s 随机数与针对消息的随机数密钥相同，请您重新生成")
	}
	signer.R_S = &r_s.PublicKey
	signer.C_S = HashToZq(DotProduct(signer.SK_S, signer.PK_S), signer.R_S)
	signer.S_S = ComputeS_S(r_s, signer.C_S, msg.SK_M)

	/* 开始签名工作 */
	// 第一步对于所有 i 不等于 signer 的用户公钥计算 H_i
	var randomPoint []*ecdsa.PublicKey // 用于存储所有生成的 U_i
	for i := 0; i < len(list)-1; i++ { // 循环只到 len(list)-1
		U_iKey, err := crypto.GenerateKey()
		if err != nil {
			panic(fmt.Sprintf("Failed to generate U_i: %v", err))
		}
		randomPoint = append(randomPoint, &U_iKey.PublicKey)
	}
	// 初始化 List_Hi 用于存储 H_i
	var List_Hi []*ecdsa.PrivateKey
	var mu sync.Mutex     // 互斥锁保护共享资源
	var wg sync.WaitGroup // 并发同步
	// 并行计算 H_i
	for i := 0; i < len(list)-1; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			U_i := randomPoint[i] // 对应的 U_i
			H_i := HashToZq(msg.Text, list, U_i)
			// 保护 List_Hi 的并发安全
			mu.Lock()
			List_Hi = append(List_Hi, H_i)
			mu.Unlock()
		}(i)
	}
	wg.Wait() // 等待所有并发任务完成
	/* 计算得到 U_i */

	return
}

// ComputeS_S 计算 S_S = (r_s - C_S * sk_M) mod q
func ComputeS_S(r_s, C_S, sk_M *ecdsa.PrivateKey) *ecdsa.PrivateKey {
	// 获取 secp256k1 曲线和曲线阶 q
	curve := crypto.S256()
	curveOrder := curve.Params().N

	// 提取私钥值
	rValue := r_s.D
	cValue := C_S.D
	skValue := sk_M.D

	// 计算 S_S = (r_s - C_S * sk_M) mod q
	product := new(big.Int).Mul(cValue, skValue) // C_S * sk_M
	result := new(big.Int).Sub(rValue, product)  // r_s - (C_S * sk_M)
	result.Mod(result, curveOrder)               // 结果取模 q 确保在有限域内

	// 将结果封装为新的 *ecdsa.PrivateKey
	S_S := &ecdsa.PrivateKey{
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

// DotProduct 实现椭圆曲线点的标量乘法
func DotProduct(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) *ecdsa.PublicKey {
	// 获取 secp256k1 曲线
	curve := crypto.S256()

	// 提取私钥值 d 和公钥点 (X, Y)
	d := privateKey.D
	pubX := publicKey.X
	pubY := publicKey.Y

	// 使用椭圆曲线的标量乘法公式：result = d * (pubX, pubY)
	newX, newY := curve.ScalarMult(pubX, pubY, d.Bytes())

	// 将结果装载为 *ecdsa.PublicKey 并返回
	result := &ecdsa.PublicKey{
		Curve: curve,
		X:     newX,
		Y:     newY,
	}
	return result
}

// HashToZq 根据输入参数生成符合 secp256k1 曲线要求的私钥
func HashToZq(args ...interface{}) *ecdsa.PrivateKey {
	// 获取 secp256k1 曲线实例和曲线阶 q
	curve := crypto.S256()
	curveOrder := curve.Params().N

	var concatenated []byte

	// 拼接输入参数为字节数组
	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			concatenated = append(concatenated, []byte(v)...)
		case []byte:
			concatenated = append(concatenated, v...)
		case *ecdsa.PublicKey:
			concatenated = append(concatenated, v.X.Bytes()...)
			concatenated = append(concatenated, v.Y.Bytes()...)
		case *ecdsa.PrivateKey:
			concatenated = append(concatenated, v.D.Bytes()...)
		case *big.Int:
			concatenated = append(concatenated, v.Bytes()...)
		default:
			panic(fmt.Sprintf("Unsupported type: %T", v))
		}
	}

	// 计算 SHA256 哈希
	hash := sha256.Sum256(concatenated)
	d := new(big.Int).SetBytes(hash[:])

	// 将 d 限制在曲线阶内：d = d mod q
	d.Mod(d, curveOrder)

	// 特殊情况：如果 d == 0，则设为 1（避免生成无效私钥）
	if d.Sign() == 0 {
		d.SetInt64(1)
	}

	// 使用生成的 d 创建私钥
	privateKey := &ecdsa.PrivateKey{
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
