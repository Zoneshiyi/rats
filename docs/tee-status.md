# TEE 状态详解

## Binding 状态语义

最终 token 的 `rats.challenge_binding` 字段有两种取值：

- **`hardware_verified`**：evidence 中由硬件保护的字段（CCA realm challenge / CSV attestation report 的 report data 等）与 challenge token 中的 nonce 完全一致或满足零填充关系，且 evidence 自身的硬件可信链已完整校验通过。
- **`simulated`**：本次 attestation 没有经过完整的硬件可信链校验。出现该标签即表示 token **不能**作为生产环境的可信声明。

## 各 TEE 当前状态

### CCA — `hardware_verified`

依赖 `ccatoken` crate 完成 CBOR 解析与 COSE 签名校验。`verify_challenge_binding()` 比对 realm challenge 与 challenge nonce。fixture 缺字段时拒签。

### CSV — `hardware_verified`

仅接受 trustee-style envelope。具备：

- attestation report V1 / V2 解析
- `HRK → HSK → CEK → PEK` 证书链校验（本地 bundle / 可选 KDS 下载）
- `PEK` 对 attestation report 的 SM2/SM3 签名校验
- `report_data` 与 challenge nonce 比对

Appraisal policy（当前已落地以下两条规则，更完整的策略表达式仍在演进）：

- `csv_allowed_measurements` 白名单匹配 `measure`
- `policy.debug` 必须为 `false`（debug=on 允许调试器读 guest 内存）

### TDX — `simulated`

当前仅做：

- `Quote::from_bytes()` 解析
- `quote.verify()` 自签名校验
- `report_input_data` 与 challenge nonce 比对

**未实现**：

- DCAP QVL / PCCS / collateral 真实验证链
- PCK chain 与 Intel PCS 交叉验证
- TCB / SVN / RTMR 策略校验
- QE / TD module identity 校验

为避免 token 谎称硬件可信，binding 标签当前为 `simulated`，DCAP 链路真正接入后将切回 `hardware_verified`。

### Kunpeng — `simulated`

guest-components 当前不支持 Kunpeng，无法接入真实取证。仅做 JSON 字段提取与 EAR 输出，作为协议占位。

## 为什么不引入第三档 binding 状态

考虑过 `HardwareVerifiedPartial`（仅部分硬件链路可信）作为 TDX 当前阶段的标签。最终拒绝，理由：

- `HardwareVerified` 的语义必须严格意味"完整可信链"，否则 RP 端无法据此做安全决策；
- 任何"部分可信"都属于 `Simulated` 范畴；
- 三态会让 RP / 审计逻辑变成多分支判断，违反"不引入不必要抽象"原则。

## challenge / report data 兼容形态

`verify_challenge_binding()` 兼容两种绑定形态，覆盖真实 TEE 常见场景：

1. evidence 中的 report data 与 nonce **完全一致**；
2. evidence 中的 report data 为 `nonce + 零填充`，常见于 64 字节固定长度的 report data 字段。

不匹配时直接拒签，不存在"降级签发 simulated"的隐藏路径——这条 invariant 由 verifier 主流程显式锁定。
