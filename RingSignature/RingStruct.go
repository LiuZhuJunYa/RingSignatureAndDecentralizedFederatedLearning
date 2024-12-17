package RingSignature

import "crypto/ecdsa"

// Message 第一种类型：消息类型
type Message struct {
	Text []byte           // 消息字符串，明文信息
	SK_M ecdsa.PrivateKey // 为了对当前消息签名，而专门选择的一个随机数密钥
	PK_M ecdsa.PublicKey  // 根据私钥生成的专门针对当前消息的公钥
}

// Signer 第二种类型：签名者类型
type Signer struct {
	SK_S ecdsa.PrivateKey // 签名者的 ECC 私钥
	PK_S ecdsa.PublicKey  // 签名者的 ECC 公钥
	R_S  ecdsa.PublicKey  // 签名者自己计算得到的参数 R_S
	C_S  ecdsa.PrivateKey // 签名者自己计算得到的参数 C_S
	S_S  ecdsa.PrivateKey // 签名者自己计算得到的参数 S_S
}

// Result 第五种类型：签名信息结果
type Result struct {
	MessageText []byte            // 消息字符串，明文信息
	PK_M        ecdsa.PublicKey   // 当前签名消息的主公钥
	List        []ecdsa.PublicKey // 环成员公钥信息
	RandomPoint []ecdsa.PublicKey // 为环成员选择的随机点集
	V           ecdsa.PrivateKey  // 公开的参数V，有限域q内的正整数
	C           ecdsa.PrivateKey  // 公开的参数C，有限域q内的正整数
	T           ecdsa.PublicKey   // 公开的参数T，通过选择随机数t，计算得到的ECC上的点
	Pi          ecdsa.PrivateKey  // 公开的参数Pi，有限域q内的正整数
}
