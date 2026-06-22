# RATS

基于 Rust workspace 的统一远程证明（Remote ATtestation procedureS）原型系统。参考 RFC 9334 与 Veraison / Trustee 生态实践，提供 challenge-first 的多 TEE 证明链路。

## 项目框架

四个核心 crate：

| Crate | 角色 | 主要职责 |
|-------|------|----------|
| `protos` | 协议层 | gRPC 协议定义、消息格式、challenge token 编解码 |
| `verifier` | 验证服务 | challenge 签发、evidence 验证、EAR/JWT 输出 |
| `attester` | 取证服务 | 取证、模式分发、转调 verifier |
| `relying-party` | CLI 客户端 | 发起远程证明、展示最终 token |

每个服务端 crate 内部分三层：

- **Core**：核心 trait 与领域类型；
- **Service**：业务编排，可单测，不依赖 gRPC；
- **API**：gRPC 适配，请求/响应映射。

## 功能

- **Challenge-first 流程**：challenge 由 verifier 签发并校验，evidence 验证前先核对 challenge token。
- **三种模式**：
  - `passport`：attester 内部完成 verifier 调用，返回最终 token；
  - `background-check`：attester 仅返回 evidence，由 RP 再调 verifier；
  - `mix`：reserved（多 evidence 聚合，待落地）。
- **多 TEE 路由**：CCA / TDX / CSV / Kunpeng 各自独立 verifier，按 `Tee` 字段路由。
- **CSV 完整链路**：trustee-style evidence 解析 + `HRK→HSK→CEK→PEK` 证书链校验 + `PEK` 对 attestation report 的签名校验。
- **Evidence 来源切换**：本地 fixture 或 guest-components Attestation Agent gRPC 取证。

## 当前 TEE 真实状态

| TEE | Binding 标签 | 说明 |
|-----|-------------|------|
| CCA | `hardware_verified` | 完整链路（解析 + 签名 + challenge 绑定） |
| CSV | `hardware_verified` | 完整链路（trustee-style + 证书链） |
| TDX | `simulated` | 仅 quote 自签，DCAP / PCCS / TCB 验证未接入 |
| Kunpeng | `simulated` | guest-components 不支持 Kunpeng，纯 mock |

详细解释见 [docs/tee-status.md](docs/tee-status.md)。

## 快速开始

### 默认 fixture 模式

三个 shell 分别启动：

```bash
cargo run -p verifier
cargo run -p attester
cargo run -p relying-party -- --mode passport
```

`relying-party` 输出最终 attestation token 与解码后的 EAR payload。

### CLI 参数

```text
relying-party [--addr HOST:PORT] [--mode passport|background-check|mix]
              [--nonce TEXT | --nonce-b64 BASE64URL]
```

- `--nonce`：测试模式下让 verifier 使用指定字符串作为 challenge nonce（要求 verifier 配置 `allow_test_nonce = true`）。
- `--nonce-b64`：传入 base64url 形式的二进制 nonce，用于让静态 fixture 中已有的 report data 与 challenge 对齐。
- `--mode mix`：当前阶段会被 attester 拒签（reserved）。

### 切换 evidence 来源到 guest-components

修改 `configs/attester.toml`：

```toml
evidence_source = "guest-components-grpc"
aa_endpoint = "http://127.0.0.1:50002"
```

或通过环境变量临时覆盖：

```bash
RATS_EVIDENCE_SOURCE=guest-components-grpc \
RATS_AA_ENDPOINT=http://127.0.0.1:50002 \
cargo run -p attester
```

需要在 confidential guest 内先运行 guest-components 的 Attestation Agent。

## 测试

```bash
cargo fmt --all
cargo test --workspace --all-features
cargo check --workspace --all-targets
```

## 实现细节文档

- [架构与三层分离](docs/architecture.md)
- [协议](docs/protocol.md)
- [TEE 状态详解](docs/tee-status.md)
- [运行与配置](docs/running.md)
