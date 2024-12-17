package RingSignature

import (
	"crypto/ecdsa"
	"fmt"
)

// Verify 验证函数
func Verify() (Result bool) {

	return
}

// Sign 签名函数
func Sign(Message string, Signer Signer, PK_List []ecdsa.PublicKey) (Result Result) {
	msg := CreateMessage(Message)       // 创建签名消息
	signer := CreateSigner(Signer, msg) // 创建签名者信息

	// 快速打印 Message、Signer 结构体的内容
	fmt.Printf("Message Details:\n%+v\n", msg)
	fmt.Printf("Signer Details:\n%+v\n", signer)

	return
}

//func Sign(message string, signer *Signer, list []*ecdsa.PublicKey) (sign_result *Result, err error) {
//
//	/* 开始签名工作 */
//	// 第一步对于所有 i 不等于 signer 的用户公钥计算 H_i
//	var randomPoint []*ecdsa.PublicKey // 用于存储所有生成的 U_i
//	for i := 0; i < len(list)-1; i++ { // 循环只到 len(list)-1
//		U_iKey, err := crypto.GenerateKey()
//		if err != nil {
//			panic(fmt.Sprintf("生成随机数 U_i 失败: %v", err))
//		}
//		randomPoint = append(randomPoint, &U_iKey.PublicKey)
//	}
//	// 初始化 List_Hi 用于存储 H_i
//	List_Hi := make([]*ecdsa.PrivateKey, len(randomPoint)) // 预分配长度，确保顺序一致
//	var wg sync.WaitGroup                                  // 并发同步
//	// 并行计算 H_i
//	for i := 0; i < len(randomPoint); i++ {
//		wg.Add(1)
//		go func(i int) {
//			defer wg.Done()
//			U_i := randomPoint[i]                // 对应的 U_i
//			H_i := HashToZq(msg.Text, list, U_i) // 计算 H_i
//			// 按索引直接存入，确保顺序与 U_i 一致
//			List_Hi[i] = H_i
//		}(i)
//	}
//	wg.Wait() // 等待所有并发任务完成
//	/* 第二步计算得到 U_S */
//	r_S_Pi, err := crypto.GenerateKey() // 随机选择一个 r_S_Pi 属于 Zq*
//	if err != nil {
//		panic(fmt.Sprintf("生成随机数 r_S_Pi 失败: %v", err))
//	}
//	filteredList, index_PK_S := RemoveSigner(list, signer.PK_S)                     // 剔除签名者公钥并记录其下标
//	U_S, err := ComputeU_S(r_S_Pi, signer.PK_S, randomPoint, List_Hi, filteredList) // 计算 U_S
//	if err != nil {
//		panic(fmt.Sprintf("计算 U_S 失败: %v", err))
//	}
//	list = append(filteredList[:index_PK_S], append([]*ecdsa.PublicKey{signer.PK_S}, filteredList[index_PK_S:]...)...) // 将 PK_S 放回原位置
//	randomPoint = append(randomPoint[:index_PK_S], append([]*ecdsa.PublicKey{U_S}, randomPoint[index_PK_S:]...)...)    // 将 U_S 放到 randomPoint 的对应位置
//	//sign_result.List = list
//	//sign_result.RandomPoint = randomPoint
//	/* 第三步计算 H_S 和 V */
//	H_S := HashToZq(msg.Text, list, U_S)
//	List_Hi = append(List_Hi[:index_PK_S], append([]*ecdsa.PrivateKey{H_S}, List_Hi[index_PK_S:]...)...)
//	V := ComputeV(signer.SK_S, r_S_Pi, H_S)
//	//sign_result.V = V
//	/* 第四步计算 T 和 c */
//	t, err := crypto.GenerateKey() // 随机选择一个 t 属于 Zq*
//	if err != nil {
//		panic(fmt.Sprintf("生成随机数 t 失败: %v", err))
//	}
//	T := t.PublicKey // 计算 T=t*P
//	c, err := ComputeC(signer.SK_S, signer.PK_S, msg.PK_M, signer.C_S, signer.S_S)
//	if err != nil {
//		panic(fmt.Sprintf("计算 c 失败: %v", err))
//	}
//	//sign_result.T = &T
//	//sign_result.C = c
//	/* 第五步计算 e 和 pi */
//	e := HashToZq(list, msg.Text, T, c)
//	pi, err := ComputePi(t, e, signer.S_S)
//
//	/* 公示签名结果 */
//	sign_result = &Result{
//		MessageText: msg.Text,
//		PK_M:        msg.PK_M,
//		List:        list,
//		RandomPoint: randomPoint,
//		V:           V,
//		C:           c,
//		T:           &T,
//		Pi:          pi,
//	}
//	return
//}
//
//func Verify(sign *Result) bool {
//	// 第一步：计算得到所有的 H_i
//	List_Hi := make([]*ecdsa.PrivateKey, len(sign.RandomPoint)) // 预分配长度，确保顺序一致
//	var wg sync.WaitGroup                                       // 并发同步
//	// 并行计算 H_i
//	for i := 0; i < len(sign.RandomPoint); i++ {
//		wg.Add(1)
//		go func(i int) {
//			defer wg.Done()
//			U_i := sign.RandomPoint[i]                        // 对应的 U_i
//			H_i := HashToZq(sign.MessageText, sign.List, U_i) // 计算 H_i
//			// 按索引直接存入，确保顺序与 U_i 一致
//			List_Hi[i] = H_i
//		}(i)
//	}
//	wg.Wait() // 等待所有并发任务完成
//
//	// 第二步：计算 e
//	e := HashToZq(sign.List, sign.MessageText, sign.T, sign.C)
//
//	// 第三步：先计算哈希的第一部分
//	sumRandom := ComputeSum(sign.RandomPoint, List_Hi, sign.List)
//	first := ScalarMultPrivateKeyWithPublicKey(sign.V, sumRandom)
//	// 然后计算第二部分
//	second := ComputeHashPart2(sign.C, sign.PK_M, e, sign.T, sign.Pi)
//	equalPart := HashToZq(first, second)
//	flag := ComparePrivateKeys(sign.C, equalPart)
//	return flag
//}
//
//// 比较两个私钥是否相同
//func ComparePrivateKeys(key1, key2 *ecdsa.PrivateKey) bool {
//	if key1 == nil || key2 == nil {
//		return false // 任意一个私钥为 nil，则不相同
//	}
//	// 比较私钥值 D
//	return key1.D.Cmp(key2.D) == 0
//}
//
//// ComputeHashPart2 计算哈希的第二部分内容
//func ComputeHashPart2(C *ecdsa.PrivateKey, PK_M *ecdsa.PublicKey, e *ecdsa.PrivateKey, T *ecdsa.PublicKey, Pi *ecdsa.PrivateKey) *ecdsa.PublicKey {
//	curve := crypto.S256()         // secp256k1 曲线
//	curveOrder := curve.Params().N // 曲线阶 q
//
//	// Step 1: 计算 C * PK_M
//	C_PK_M_X, C_PK_M_Y := curve.ScalarMult(PK_M.X, PK_M.Y, C.D.Bytes())
//
//	// Step 2: 计算 Pi * P
//	Pi_P_X, Pi_P_Y := curve.ScalarBaseMult(Pi.D.Bytes())
//
//	// Step 3: 计算 T - Pi * P
//	T_minus_Pi_P_X, T_minus_Pi_P_Y := curve.Add(T.X, T.Y, new(big.Int).Neg(Pi_P_X), new(big.Int).Neg(Pi_P_Y))
//
//	// Step 4: 计算 e^(-1)
//	eInverse := new(big.Int).ModInverse(e.D, curveOrder)
//
//	// Step 5: 计算 e^(-1) * (T - Pi * P)
//	eInverse_T_minus_Pi_P_X, eInverse_T_minus_Pi_P_Y := curve.ScalarMult(T_minus_Pi_P_X, T_minus_Pi_P_Y, eInverse.Bytes())
//
//	// Step 6: 计算 C * PK_M + e^(-1) * (T - Pi * P)
//	final_X, final_Y := curve.Add(C_PK_M_X, C_PK_M_Y, eInverse_T_minus_Pi_P_X, eInverse_T_minus_Pi_P_Y)
//
//	// 构造结果公钥
//	return &ecdsa.PublicKey{
//		Curve: curve,
//		X:     final_X,
//		Y:     final_Y,
//	}
//}
//
//// ScalarMultPrivateKeyWithPublicKey 实现 *ecdsa.PrivateKey * *ecdsa.PublicKey
//func ScalarMultPrivateKeyWithPublicKey(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) *ecdsa.PublicKey {
//	curve := crypto.S256() // secp256k1 曲线
//
//	// 使用椭圆曲线标量乘法公式：result = privateKey.D * publicKey
//	X, Y := curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())
//
//	// 构造结果公钥
//	resultPublicKey := &ecdsa.PublicKey{
//		Curve: curve,
//		X:     X,
//		Y:     Y,
//	}
//	return resultPublicKey
//}
//
//// Sign 环签名函数

//// ComputePi 计算 π 的函数
//func ComputePi(t, e, S_S *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
//	curve := crypto.S256()         // secp256k1 曲线
//	curveOrder := curve.Params().N // 曲线阶 q
//
//	// Step 1: 计算 e * S_S
//	product := new(big.Int).Mul(e.D, S_S.D)
//	product.Mod(product, curveOrder) // 确保结果在有限域内
//
//	// Step 2: 计算 t - (e * S_S)
//	result := new(big.Int).Sub(t.D, product)
//	result.Mod(result, curveOrder) // 确保结果在有限域内
//
//	// Step 3: 构造结果私钥
//	privateKey := &ecdsa.PrivateKey{
//		PublicKey: ecdsa.PublicKey{
//			Curve: curve,
//			X:     nil,
//			Y:     nil,
//		},
//		D: result,
//	}
//	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(result.Bytes())
//
//	return privateKey, nil
//}
//
//// ComputeC 计算 c 的函数
//func ComputeC(SK_S *ecdsa.PrivateKey, PK_S, pk_m *ecdsa.PublicKey, C_S, S_S *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
//	curve := crypto.S256() // secp256k1 曲线
//
//	// Step 1: 计算 T_1 = SK_S * PK_S
//	T1_X, T1_Y := curve.ScalarMult(PK_S.X, PK_S.Y, SK_S.D.Bytes())
//
//	// Step 2: 计算 T_2 = C_S * pk_m + S_S * P
//	// C_S * pk_m
//	CS_X, CS_Y := curve.ScalarMult(pk_m.X, pk_m.Y, C_S.D.Bytes())
//
//	// S_S * P
//	SS_X, SS_Y := curve.ScalarBaseMult(S_S.D.Bytes())
//
//	// T_2 = C_S * pk_m + S_S * P
//	T2_X, T2_Y := curve.Add(CS_X, CS_Y, SS_X, SS_Y)
//
//	// Step 3: 调用 HashToZq，计算 c
//	T1 := &ecdsa.PublicKey{Curve: curve, X: T1_X, Y: T1_Y}
//	T2 := &ecdsa.PublicKey{Curve: curve, X: T2_X, Y: T2_Y}
//
//	c := HashToZq(T1, T2)
//	return c, nil
//}
//
//// ComputeV 计算 V
//func ComputeV(SK_S, r_S_Pi, H_S *ecdsa.PrivateKey) *ecdsa.PrivateKey {
//	curve := crypto.S256()         // secp256k1 曲线
//	curveOrder := curve.Params().N // 曲线阶 q
//
//	// 1. 计算 r_S_Pi + H_S
//	sum := new(big.Int).Add(r_S_Pi.D, H_S.D)
//	sum.Mod(sum, curveOrder) // 确保在有限域内
//
//	// 2. 计算 (r_S_Pi + H_S)^(-1)
//	inverse := new(big.Int).ModInverse(sum, curveOrder)
//	if inverse == nil {
//		fmt.Errorf("计算 (r_S_Pi + H_S)^(-1) 失败")
//		return nil
//	}
//
//	// 3. 计算 V = SK_S * inverse
//	V := new(big.Int).Mul(SK_S.D, inverse)
//	V.Mod(V, curveOrder) // 确保结果在有限域内
//
//	// 4. 创建返回值 *ecdsa.PrivateKey
//	privateKey := &ecdsa.PrivateKey{
//		PublicKey: ecdsa.PublicKey{
//			Curve: curve,
//			X:     nil,
//			Y:     nil,
//		},
//		D: V,
//	}
//	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(V.Bytes())
//	return privateKey
//}
//
//// RemoveSigner 从列表中剔除签名者公钥，同时返回其下标
//func RemoveSigner(list []*ecdsa.PublicKey, PK_S *ecdsa.PublicKey) ([]*ecdsa.PublicKey, int) {
//	filtered := []*ecdsa.PublicKey{}
//	index_PK_S := -1
//
//	for i, pk := range list {
//		if pk.X.Cmp(PK_S.X) == 0 && pk.Y.Cmp(PK_S.Y) == 0 {
//			index_PK_S = i // 记录签名者公钥的下标
//		} else {
//			filtered = append(filtered, pk)
//		}
//	}
//	return filtered, index_PK_S
//}
//
//// NegatePoint 实现椭圆曲线点的取反操作
//func NegatePoint(pubKey *ecdsa.PublicKey) (*big.Int, *big.Int) {
//	curve := pubKey.Curve
//	p := curve.Params().P // 获取有限域的模数 p
//	negY := new(big.Int).Sub(p, pubKey.Y)
//	negY.Mod(negY, p) // 确保结果在有限域内
//	return pubKey.X, negY
//}
//
//func ComputeSum(randomPoint []*ecdsa.PublicKey, List_Hi []*ecdsa.PrivateKey, list []*ecdsa.PublicKey) *ecdsa.PublicKey {
//	// 计算 Σ(randomPoint[i] + List_Hi[i] * list[i])
//	curve := crypto.S256() // secp256k1 曲线
//
//	sumX, sumY := big.NewInt(0), big.NewInt(0)
//	for i := 0; i < len(randomPoint); i++ {
//		// List_Hi[i] * list[i]
//		hx, hy := curve.ScalarMult(list[i].X, list[i].Y, List_Hi[i].D.Bytes())
//
//		// randomPoint[i] + List_Hi[i] * list[i]
//		rpx, rpy := curve.Add(randomPoint[i].X, randomPoint[i].Y, hx, hy)
//
//		// 累加到总和
//		sumX, sumY = curve.Add(sumX, sumY, rpx, rpy)
//	}
//	return &ecdsa.PublicKey{
//		Curve: curve,
//		X:     sumX,
//		Y:     sumY,
//	}
//}
//
//// ComputeU_S 计算 U_S
//func ComputeU_S(r_S_Pi *ecdsa.PrivateKey, PK_S *ecdsa.PublicKey, randomPoint []*ecdsa.PublicKey, List_Hi []*ecdsa.PrivateKey, list []*ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
//	curve := crypto.S256() // secp256k1 曲线
//
//	if len(randomPoint) != len(List_Hi) || len(List_Hi) != len(list) {
//		return nil, fmt.Errorf("mismatched lengths: randomPoint, List_Hi, and list must have the same length")
//	}
//
//	// 1. 计算 r_S_Pi * PK_S
//	r_S_Pi_X, r_S_Pi_Y := curve.ScalarMult(PK_S.X, PK_S.Y, r_S_Pi.D.Bytes())
//
//	// 2. 计算 Σ(randomPoint[i] + List_Hi[i] * list[i])
//	sumX, sumY := big.NewInt(0), big.NewInt(0)
//	for i := 0; i < len(randomPoint); i++ {
//		// List_Hi[i] * list[i]
//		hx, hy := curve.ScalarMult(list[i].X, list[i].Y, List_Hi[i].D.Bytes())
//
//		// randomPoint[i] + List_Hi[i] * list[i]
//		rpx, rpy := curve.Add(randomPoint[i].X, randomPoint[i].Y, hx, hy)
//
//		// 累加到总和
//		sumX, sumY = curve.Add(sumX, sumY, rpx, rpy)
//	}
//
//	// 3. 计算 -Σ(...) = NegatePoint(Σ(...))
//	negSumX, negSumY := NegatePoint(&ecdsa.PublicKey{Curve: curve, X: sumX, Y: sumY})
//
//	// 4. 计算 U_S = r_S_Pi * PK_S + (-Σ(...))
//	U_S_X, U_S_Y := curve.Add(r_S_Pi_X, r_S_Pi_Y, negSumX, negSumY)
//
//	// 5. 返回结果 U_S 作为 *ecdsa.PublicKey
//	return &ecdsa.PublicKey{
//		Curve: curve,
//		X:     U_S_X,
//		Y:     U_S_Y,
//	}, nil
//}
//
