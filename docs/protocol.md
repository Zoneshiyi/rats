# 协议

完整 proto 定义见 [`protos/attestation.proto`](../protos/attestation.proto)。本文重点说明语义。

## 服务

### `AttestationService`（attester 暴露）

| RPC | 用途 |
|-----|------|
| `GetChallenge` | RP 通过 attester 转向 verifier 申请 challenge |
| `AttestationEvaluate` | passport / background-check / mix 三种模式的统一入口 |
| `VerificationEvaluate` | background-check 模式下 RP 第二步调用 |

### `VerifierService`（verifier 暴露）

| RPC | 用途 |
|-----|------|
| `IssueChallenge` | 签发 challenge token |
| `Verify` | 验证 evidence 并签发最终 attestation token |

## 关键消息

### Challenge Token

verifier 签发，HMAC-SHA256 签名（结构类似 JWT，但 `typ = RATS_CHALLENGE`）。载荷字段：

| 字段 | 含义 |
|------|------|
| `tee` | 期望的 TEE 类型 |
| `mode` | 期望的工作模式 |
| `nonce` | challenge nonce 的 base64url 字符串 |
| `issued_at` | 签发时间（Unix 秒） |
| `expires_at` | 过期时间（默认 TTL 300 秒） |

verifier 在 `Verify` 入口处校验 token 签名、过期、tee 匹配；challenge consume-once 防重放见 ADR 0005。

### Mode 取值

| 取值 | 行为 |
|------|------|
| `MODE_PASSPORT` | attester 内部完成 verifier 调用，返回 attestation token |
| `MODE_BACKGROUND_CHECK` | attester 仅返回 evidence list |
| `MODE_MIX` | reserved，attester 当前直接拒签（多 evidence 聚合方案见 ADR 0004） |

### Tee 取值

| 取值 | 状态 |
|------|------|
| `TEE_CCA` | 完整链路 |
| `TEE_TDX` | Simulated（DCAP 待接入） |
| `TEE_CSV` | 完整链路（trustee-style） |
| `TEE_KUNPENG` | Simulated（占位） |

### EvidenceSource 取值（ADR 0006，待落地）

`evidence_source` 字段从字符串提升为协议级 enum：

```proto
enum EvidenceSource {
  EVIDENCE_SOURCE_UNSPECIFIED = 0;
  EVIDENCE_SOURCE_FILE_BACKED = 1;
  EVIDENCE_SOURCE_GUEST_COMPONENTS_GRPC = 2;
}
```

verifier 收到 `Unspecified`（含未知值）时拒签为 `InvalidArgument`。

### ErrorCode

| 取值 | 场景 |
|------|------|
| `OK` | 成功 |
| `INVALID_ARGUMENT` | challenge 无效、字段缺失、challenge 已消费等 |
| `INTERNAL` | verifier 内部错误（取证失败、签名失败等） |
| `UNSUPPORTED_MODE` | mode 字段为 reserved 取值（如当前的 mix） |

## 流程时序

### Passport 模式

```text
RP                    attester                   verifier
 │                       │                          │
 │ GetChallenge          │                          │
 ├──────────────────────>│ IssueChallenge           │
 │                       ├─────────────────────────>│
 │                       │<─────────────────────────┤
 │<──────────────────────┤  challenge_token         │
 │                       │                          │
 │ AttestationEvaluate   │                          │
 ├──────────────────────>│ 取证                     │
 │                       │ Verify                   │
 │                       ├─────────────────────────>│
 │                       │<─────────────────────────┤
 │<──────────────────────┤  attestation_token       │
```

### Background-Check 模式

第一段相同；`AttestationEvaluate` 返回的是 evidence list，RP 自行调用 `VerificationEvaluate` 完成第二段。
