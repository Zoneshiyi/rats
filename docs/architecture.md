# 架构与三层分离

## 总览

四个 crate 之间的调用关系：

```text
relying-party ──gRPC──> attester ──gRPC──> verifier
                            │
                            └──gRPC──> guest-components AA（可选）
```

`relying-party` 永远是发起方；`attester` 与 `verifier` 各自暴露 gRPC 服务；`attester` 在 `evidence_source = "guest-components-grpc"` 时作为 AA 的客户端取证。

## 三层分离

每个服务端 crate（verifier / attester / relying-party）按相同结构组织：

| 层 | 文件 | 职责 |
|----|------|------|
| Core | `core.rs` | trait 定义、领域类型、与协议无关的纯逻辑 |
| Service | `service.rs` | 业务流程编排，依赖 Core trait，可单测 |
| API | `api.rs` | gRPC 请求/响应映射、错误码转换 |

直接收益：

- Service 层不感知 gRPC，单测无需启动 server
- TEE / 取证实现可通过 trait 注入替换
- API 层很薄，几乎只负责字段映射

## verifier 关键结构

- `Verifier` trait：每种 TEE 的验证入口，返回最终 EAR/JWT token；
- `VerifierFactory`：按 `Tee` 路由到具体 verifier 实现；
- `ChallengeTokenManager`：challenge token 的签发与校验，service 层注入；
- `ChallengeReplayGuard`：challenge consume-once 防重放（`InMemoryChallengeReplayGuard` 已在 `verifier::service` 实现，verifier 在 `Verify` 入口处调用 `try_consume`）；
- `VerificationContext`：贯穿验证流程的上下文（challenge claims、evidence_source、appraisal policy）；
- `VerifierApplicationService`：编排 `issue_challenge` 与 `verify` 两个核心流程。

## attester 关键结构

- `Attester` trait：取证入口，返回 `Vec<AttesterEvidence>`；
- 实现：
  - `FileBackedAttester`：读取本地 fixture（默认）；
  - `GuestComponentsGrpcAttester`：调用 guest-components AA gRPC 取证；
- `VerifierGateway` trait：调 verifier gRPC 的抽象，service 层注入；
- `AttesterApplicationService`：按 `Mode` 分发流程（passport 内部消化、background-check 仅返回 evidence、mix 当前拒签）。

## relying-party 关键结构

- `AttestationGateway` trait：调 attester gRPC 的抽象（CLI 一次性会话语义，使用 `&mut self`）；
- `RelyingPartyApplicationService`：编排"取 challenge → 取证 → 按需 verify → 输出 token"；
- `CliArgs`：参数解析，与 `RelyingPartyConfig` 合并。

## EAR/JWT token 输出字段

最终 token 的 RATS 自定义扩展字段：

| 字段 | 含义 |
|------|------|
| `eat_nonce` | challenge nonce 的 base64url 编码 |
| `rats.challenge_binding` | `hardware_verified` 或 `simulated`（见 [tee-status.md](tee-status.md)） |
| `rats.evidence_source` | `file-backed` 或 `guest-components-grpc` |
| `rats.appraisal_policy_id` | 可选，appraisal 策略标识（仅供审计阅读） |
| `rats.appraisal_result` | 可选，appraisal 结果，目前仅 `passed` |

每种 TEE 还会写入自己的 submod appraisal（如 `submods["cca"]`、`submods["tdx"]`），承载 TEE 特定字段。
