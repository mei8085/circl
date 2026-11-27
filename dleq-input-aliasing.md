# DLEQ 批量证明的输入共享与输出别名分析

范围：`zk/dleq`（通用证明与 RFC 9497 固定生成元入口）、`zk/dl`（Schnorr NIZK）、
`zk/qndleq`（Qn 上的 Chaum–Pedersen），以及它们依赖的 `group` 包四个群实现
（P-256、P-384、P-521、ristretto255）和唯一的内部消费者 `oprf`。

结论先行：**`zk/dleq` 在单次调用内对任何输入指针共享（别名）都是安全的，证明只
绑定调用时刻各对象的取值；包自身从不把调用方对象当作输出接收器，也不修改任何输入
的语义值。会使证明脱离原始批次的，全部是调用方在两次调用之间对共享对象做原地写
入，或用别名替换了原本代数成立的元组。** 实测矩阵（14 个用例 × 4 个群，见附录 A）
与本结论一致。

---

## 1. 背景：原地运算模型与"别名"的两个层面

`group.Element` / `group.Scalar` 的所有算术方法都是接收器原地写入风格：

```go
Add(x, y Element) Element   // receiver = x + y
Mul(x Element, s Scalar) Element // receiver = s * x
```

Go 的接口值承载指针，因此同一底层对象可以同时出现在接收器和参数位置，或同时出现在
两个不同的逻辑槽位中。需要区分两个层面：

1. **调用前的代数关系（pre-call）**：各槽位在进入 `Prove*` / `Verify*` 时的取值满足
   什么关系。例如 `kbi[j] == [k] bi[j]` 是否成立、两个槽位是否恰好指向同一对象。
2. **运算后的对象状态（post-call）**：调用返回后，调用方传入的对象是否仍然保持进入
   时的取值，后续还能否作为同一批材料继续使用。

证明与批次的对应关系完全由**调用时刻序列化进挑战/种子的字节**决定
（`computeComposites` 与 `doChallenge`，`zk/dleq/dleq.go:150-240`）。调用之后对象如何
变化不改变已经生成的 `Proof{c,s}`，但会改变下一次验证看到的批次。

---

## 2. 群运算后端对自别名的支持

`zk/dleq` 内部存在接收器与参数同对象的原地累积（见 §3）。其正确性依赖后端对
`z.Op(z, x)` 自别名的支持。逐层核实如下。

### 2.1 P-256 / P-521（`group/short.go` 的 `wElt`/`wScl`，包装标准库）

- `wElt.Add`（`short.go:205`）调用 `crypto/elliptic` 的 nistCurve.Add，标准库先用
  `pointFromAffine` 把入参复制进全新的 nistec 点，再返回两个新分配的 `*big.Int`
  （`crypto/elliptic/nistec.go:174-184`）；`wElt.Mul` 的 `ScalarMult` 同理
  （`nistec.go:209-220`）。接收器与入参是否同对象均不影响结果。
- `wScl.Add/Sub/Mul`（`short.go:345-364`）把入参字节读入新 `big.Int` 后计算，再经
  `SetBigInt` 写回接收器；`math/big` 的契约明确允许接收器与入参别名。

### 2.2 P-384（`ecc/p384` 优化实现）

`curve.Add` / `curve.ScalarMult`（`ecc/p384/p384opt.go:42-46, 82-124`）同样先
`newAffinePoint(x1,y1)` 复制入参、在全新的投影点上计算，最后 `toInt()` 返回新对象，
自别名安全。

### 2.3 ristretto255（`group/ristretto255.go`，包装 `go-ristretto v1.2.4`）

- 点加：`ExtendedPoint.Add` 先把结果写入局部 `CompletedPoint` 再回写接收器
  （`edwards25519/curve.go:198-203`）；标量乘：先建查找表、`p.SetZero()` 后逐位累积，
  全程以局部变量 `t` 中转（`curve.go:361-406`）。
- 标量加/减/乘：先把入参所有 limb 读入局部变量再写接收器
  （`scalar.go:122-140, 753-804`）。

**四个后端的 `Add`/`Mul`/`Sub`/`Neg`/`Set` 均支持接收器与任意入参同对象。** 这是
`zk/dleq` 内部自别名正确性的实际地基；但该保证来自后端实现，`group` 包的接口文档
目前没有明文承诺，属于事实上的行为而非契约（见 §7 建议 R3）。

### 2.4 一个需要记录的接收器副作用

`wElt.MarshalBinaryCompress`（`short.go:251-258`）在序列化前对接收器做
`e.x.Mod(e.x, P)`、`e.y.Mod(e.y, P)` 的原地归一化。对合法曲线上点这是幂等的
（坐标本就在域内），不改变语义值，实测 case13 也验证 prove+verify 后输入不变；
但严格意义上这是 dleq 路径上唯一会写调用方元素对象的地方。ristretto255 的序列化
无此副作用。

---

## 3. 批量证明内部的别名接触点

### 3.1 `computeComposites`（`zk/dleq/dleq.go:150-225`，证明与验证共用）

```go
m = p.G.Identity()   // 每次新对象
z = p.G.Identity()
for j := range bi {
    Mj := p.G.NewElement()      // 每轮新对象
    Mj.Mul(bi[j], dj)
    m.Add(m, Mj)                // 接收器与第一参数同对象（自别名）
    if k == nil {               // 验证路径
        Zj := p.G.NewElement()
        Zj.Mul(kbi[j], dj)
        z.Add(z, Zj)            // 自别名
    }
}
if k != nil { z.Mul(m, k) }     // 证明路径：z 是全新对象，与 m 不同
```

- 累积器 `m`、`z` 都是函数内新建对象，**不可能与调用方的任何输入别名**。
- 两处 `m.Add(m, Mj)` / `z.Add(z, Zj)` 是包内自别名，由 §2 的后端保证支持。
- 挑战系数 `dj = HashToScalar(...)` 每轮新生成；其输入是 `bi[j]`、`kbi[j]` 的
  **序列化字节副本**，后续对原对象的任何写入都影响不到已经算出的 `dj`。
- 证明路径（`k != nil`）直接令 `z = [k]m`，**完全不读取 `kbi[j]` 的群值**，
  `kbi` 只参与 `dj` 的种子哈希。这意味着：证明方若在 `kbi` 槽位放错对象，改变的是
  系数 `dj`，而验证方用 `k=nil` 重算时会同时重算 `dj` 并真正计算 `[dj]kbi[j]`；
  两侧对同一组（错误）输入仍能得到一致转录，但此时语句本身为假，
  Chaum–Pedersen 等式 `[s]M + [c]Z == [rnd]M` 不成立，验证返回 false（实测 case02b）。

### 3.2 `proveBatchWithRandomness`（`dleq.go:93-148`）

```go
t2 := p.G.NewElement().Mul(a, rnd)   // 新接收器
t3 := p.G.NewElement().Mul(M, rnd)
ss := p.G.NewScalar()
ss.Mul(cc, k)                        // 新接收器读 k
ss.Sub(rnd, ss)                      // 新接收器读 rnd
```

所有输出接收器均为新对象。`ss.Sub(rnd, ss)` 中第一参数 `rnd` 是调用方对象、接收器
是新对象，不存在自别名；即使调用方让 `rnd` 与 `k` 同指针（实测 case06），后端按值
读取，`k` 也保持不变。

### 3.3 `verifyBatch`（`dleq.go:258-316`）

`sA, ckA, t2, sM, cZ, t3` 全部由 `g.NewElement()` 新建，验证过程不持有任何调用方
对象的可写引用；`Verifier` 本身无状态，同一批对象可连续重复验证（实测 case14）。

### 3.4 `zk/dl` 与 `zk/qndleq`

- `zk/dl`（`dl.go:65-103`）同样只用 `NewElement()`/`NewScalar()` 新建接收器，
  `r.Sub(v, ...)`、`rG.Add(rG, ckG)` 均为新对象或自别名，不写调用方输入。
- `zk/qndleq` 基于 `math/big.Int`，所有中间量 `new(big.Int)` 分配，`Exp` 结果落入
  新对象；`big.Int` 文档允许别名。注意它是**非批量**单对证明，且文档已声明非常量时间。

---

## 4. 输入共享在何处受到支持（调用前代数关系维度）

下表中的"支持"指：不会崩溃、不破坏包内状态、证明/验证双方按同一转录求值。
实测全部在四个群上复现（附录 A）。

| 共享形式 | 是否支持 | 说明 / 实测 |
|---|---|---|
| 不同槽位指向同一对象，但取值满足全部 DLEQ 关系（如见证 `k=1` 时 `kbi[j]` 别名 `bi[j]`） | 支持 | case02、case12：验证 true |
| `a`/`ka` 与 `bi[0]` 同指针，只要 `ka==[k]a` 与批次关系同时成立 | 支持 | case03（k=1 构造）：true |
| 标量 `rnd` 与见证 `k` 同指针 | 支持 | case06：true，且 `k` 事后不变 |
| 同值不同对象（`Copy()`） | 支持 | case10：true |
| 直接复用 `G.Generator()` / `G.Identity()` 返回的对象作为输入 | 支持 | case11：true；这些工厂每次返回新对象，包内不缓存可写单例 |
| 同一批对象在 Prove 后、Verify 前不做任何写入，重复验证 | 支持 | case14：true,true |
| 槽位别名导致语句为假（如把 `kbi[1]` 改指 `bi[0]`，而 `[k]bi[1]≠bi[0]`） | 不产生有效证明 | case02b：验证 false；证明无法为假语句背书 |
| 别名替换后再恢复原批次，期望旧证明仍对应原批次 | **不支持（语义脱离）** | case02b 恢复后验证 false：证明绑定的是被污染时刻的转录 |

关键性质（实测 case09）：Prove 前快照全部输入，Prove 后把活动对象全部 `Neg` 改写，
对**快照**的验证仍然通过。这直接证明证明输出不别名任何调用方对象，证明只对应
调用时刻的取值。

---

## 5. 哪些组合会使证明不再对应原始批次（运算后对象状态维度）

包本身不制造脱离；脱离全部来自调用方在 Prove 与 Verify 之间对共享对象的原地写。
典型危险模式：

1. **原地覆盖被求值元素**：`kbi[j].Mul(bi[l], otherScalar)` 复用 `kbi[j]` 当输出
   （实测 case04，验证 false）。
2. **原地覆盖基元素**：`bi[j].Mul(...)` / `bi[j].Neg(bi[j])`（case05、case08b，
   false）。
3. **切片后备数组共享**：两个切片共享底层数组且其中一方被改写，效果等同 1/2。
4. **用别名换掉代数成立的元组后再恢复**：旧证明绑定污染期转录，恢复后的原批次无法
   验证（case02b）。
5. **跨 Prove/Verify 复用见证 `k` 并原地清零**：验证器从不读取 `k`（case07 仍
   true），所以这一项**不**破坏验证；但会破坏调用方后续自己的证明能力，属于调用方
   自损，不是 dleq 的别名缺陷。

判定准则可以一句话概括：**只要 Prove 与 Verify 两次调用看到的各槽位字节相同，
任何指针共享方式都安全；任何一次原地写改变了槽位字节，证明就与新批次脱离。**

---

## 6. 两个协议入口的边界

### 6.1 通用入口（`bindBase=true`）

`Prove / ProveWithRandomness / ProveBatch / ProveBatchWithRandomness` 与
`Verify / VerifyBatch`。

- 基元 `a` 是显式参数，其压缩序列化被绑定进挑战（`dleq.go:106-112`），因此
  `ka=[k]a` 中 `a` 可以是任意群元素（实测 case08d 的 generic 侧为 true）。
- 单元素包装 `Prove` 只是把 `b,kb` 包成长度 1 的切片（`dleq.go:49-55`），别名规则与
  批量完全相同。
- 已有测试 `TestChallengeBindsBase` 证明自适应替换基元会被拒绝。

### 6.2 RFC 9497 固定生成元入口（`bindBase=false`）

`ProveBatchRFC9497 / ProveBatchWithRandomnessRFC9497` 与 `VerifyBatchRFC9497`。

- 内部强制 `a = p.G.Generator()`（`dleq.go:90`），挑战不绑定基元字节，符合
  RFC 9497 的 VOPRF 转录。
- **键形状约束**：`ka` 必须是 `[k]G`（即 `MulGen(k)` 形态）。把通用入口那种
  `ka=[k]A`（A 随机）的键喂给 RFC9497 入口，即使 DLEQ 语句本身为真也会验证失败
  （实测 case08d：RFC9497=false 而 generic=true）。这不是别名问题，而是两个入口的
  有效性域不同。
- **参数顺序不对称**：证明侧是 `(k, ka, bi, kbi)`，验证侧是 `(ka, bi, kbi)`
  （无见证）。别名分析在两个入口上结论一致，但调用方迁移代码时容易在此出错。
- 内部消费者 `oprf` 严格遵守该约束：`VerifiableServer` 传入 `s.PublicKey().e`
  （`oprf/server.go:43-49`），客户端用服务器公钥验证（`oprf/client.go:154-161`）；
  `PartialObliviousServer` 传 `MulGen(keyProof)`（`server.go:65-71`）。`oprf` 中
  `evaluate` 总是把结果写入新分配的元素（`server.go:25-32`），不原地改写请求元素，
  天然避开了 §5 的危险模式。

### 6.3 边界对照

| 维度 | 通用入口 | RFC9497 入口 |
|---|---|---|
| 基元 | 任意 `a`，绑定进挑战 | 固定 `G`，不绑定 |
| 键形状 | `ka=[k]a`，a 任意 | 必须 `ka=[k]G` |
| 批次内指针别名 | 取值关系成立即安全 | 同左 |
| Prove/Verify 间原地写 | 证明脱离新批次 | 同左 |
| 参数签名 | Prove 含 `a`；Verify 含 `a` | 两侧均无 `a`，且顺序不对称 |

---

## 7. 兼容建议（保留合法对象复用）

以下建议按优先级排列，均为加法式、不改线格式与公开 API 签名。

- **R1（文档，零风险，推荐先行）**：在 `zk/dleq` 包注释与各 `ProveBatch*` /
  `VerifyBatch*` godoc 上明确两条契约：
  1. 函数不会修改任何输入元素/标量的语义值，输出 `Proof` 不别名调用方对象；
  2. 调用方可以在槽位间共享指针，**前提是 Prove 与 Verify 之间不得对这些对象做
     原地写**；需要复用对象做后续运算时使用 `Copy()` 或新建接收器。
  同时在 RFC9497 入口文档写明 `ka` 必须为 `[k]G` 以及两侧参数顺序差异。
- **R2（回归测试，低成本）**：把附录 A 的别名矩阵沉淀为 `dleq_test.go` 的表驱动
  测试（四群 × 合法别名/原地写脱离/快照对应/入口边界），锁住当前行为，防止后端或
  重构悄悄改变别名语义。遵循仓库"每个修复配回归测试"的惯例，这是纯测试增量。
- **R3（接口契约上收，中期）**：在 `group.Element`/`group.Scalar` 的 `Add`/`Mul`/
  `Sub`/`Neg` 文档中明文承诺接收器可与入参别名（四个后端现状都已满足）。这样
  `computeComposites` 的自别名累积就从"依赖实现细节"升级为"依赖公开契约"。
- **R4（可选防御，需权衡）**：若希望库主动拦截 §5 的危险用法，可在 `computeComposites`
  入口对 `bi`/`kbi` 做一次指针去重快照（`Copy()` 后再运算）。代价是每批 O(n) 次
  额外点拷贝，且把"调用方误用"从"验证失败"变成"静默复制"，可能掩盖真实 bug；
  当前显式失败的行为更利于发现问题，**默认不建议**，除非有明确的误用事故驱动。
- **R5（副作用收敛，可选）**：`wElt.MarshalBinaryCompress` 的原地 `Mod` 归一化
  （`short.go:255-256`）可改为在副本上归一化，彻底消除 dleq 路径对调用方元素对象的
  唯一一次写入。对合法点无行为变化，但属于 `group` 包公共行为微调，应走单独评审。
- **R6（调用方指南）**：在 `oprf` 等消费者侧保持"求值结果一律新分配"的现状；
  对外部使用者，在 README/示例中展示 `elem.Copy()` 后再原地运算的模式，而不是
  直接复用批次元素当累加器。

不建议做的事：不要改变 `computeComposites` 的转录构造或 `Proof` 编码来"解决"别名——
那会改变线格式并使现有 KAT/RFC9497 向量失效，违反 AGENTS.md 的线格式纪律。

---

## 8. 验证总结：成功验证仍归属原批次的条件

一次 DLEQ 批量证明能够在验证时归属于原始批次的公钥与元素关系，当且仅当：

1. 进入 Prove 与进入 Verify 的每个槽位（`a, ka, bi[j], kbi[j]`；RFC9497 入口为
   `ka, bi[j], kbi[j]` 且 `ka=[k]G`）具有相同的压缩序列化字节；
2. 见证关系 `ka=[k]a` 与 `kbi[j]=[k]bi[j]` 在调用时刻成立（假语句无法获得可通过
   验证的证明，case02b）；
3. 两次调用之间没有对共享对象的原地写（§5）；
4. 入口选择与键形状匹配（§6）。

指针如何共享、对象被多少个槽位引用、`rnd` 是否别名 `k`，都不影响上述归属——
包内所有算术接收器均为新对象，证明只固化调用时刻的字节转录。实测中满足 1–4 的
全部别名组合（case01/02/03/06/08/08c/09/10/11/12/13/14）在 P-256、P-384、P-521、
ristretto255 上均稳定验证通过；违反条件 1 或 2 的组合（case02b/04/05/08b/08d 的
RFC9497 侧）均稳定失败。仓库现有 `go test ./zk/...` 全部通过，未发现需要修改的
库内缺陷。

---

## 附录 A：实测矩阵（14 用例 × 4 群，结果完全一致）

验证程序独立于仓库工作区（replace 指向本仓库，离线使用本地模块缓存），
覆盖 P-256 / P-384 / P-521 / ristretto255：

| 用例 | 构造 | 期望 | 实测 |
|---|---|---|---|
| 01 | 基线，全异对象 | true | true |
| 02 | 跨槽位同指针，k=1 保持真关系 | true | true |
| 02b | 跨槽位别名制造假语句；再恢复原批次 | false / false | false / false |
| 03 | `a`、`ka` 别名 `bi[0]`，关系成立 | true | true |
| 04 | Prove 后原地覆盖 `kbi[0]` | false | false |
| 05 | Prove 后原地覆盖 `bi[0]` | false | false |
| 06 | `rnd` 与 `k` 同指针 | true，k 不变 | true，k 不变 |
| 07 | Prove 后清零见证 `k` | true（验证器不读 k） | true |
| 08 | RFC9497 基线，`ka=MulGen(k)` | true | true |
| 08b | RFC9497 Prove 后 `Neg(bi[0])` | false | false |
| 08c | RFC9497 中 `ka` 别名 `bi[0]`，关系成立 | true | true |
| 08d | 随机基元键：RFC9497 vs 通用入口 | false / true | false / true |
| 09 | Prove 后全部活动输入取反，对快照验证 | true | true |
| 10 | 同值异对象（Copy） | true | true |
| 11 | 复用 `Generator()` 返回对象为基元 | true | true |
| 12 | 单元素 `Prove` 中 b==kb 同指针，k=1 | true | true |
| 13 | Prove+Verify 后所有输入逐对象比对 | 不变 | 不变 |
| 14 | 同对象连续两次 VerifyBatch | true,true | true,true |

## 附录 B：关键代码位置

- 复合量计算与自别名累积：`zk/dleq/dleq.go:150-225`（`m.Add(m,Mj)` 在 211 行，
  `z.Add(z,Zj)` 在 216 行，`z.Mul(m,k)` 在 221 行）
- 证明侧标量响应：`zk/dleq/dleq.go:143-145`
- 验证侧全新接收器：`zk/dleq/dleq.go:274-279`
- RFC9497 固定生成元：`zk/dleq/dleq.go:84-91`
- 通用入口基元绑定：`zk/dleq/dleq.go:106-112`
- wElt 序列化原地归一化：`group/short.go:251-258`
- 后端别名安全：`group/short.go:205-228, 345-364`；`ecc/p384/p384opt.go:42-124`；
  `go-ristretto@v1.2.4/edwards25519/curve.go:198-203, 361-406`、`scalar.go:122-140, 753-804`
- 消费者安全用法：`oprf/server.go:25-55, 63-77`、`oprf/client.go:149-186`
