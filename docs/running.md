# 运行与配置

## 默认端口

| 服务 | 默认监听 |
|------|---------|
| verifier | `127.0.0.1:50061` |
| attester | `127.0.0.1:50051` |

## 配置文件

### `configs/verifier.toml`

| 字段 | 含义 |
|------|------|
| `addr` | gRPC 监听地址 |
| `verifier_build` / `verifier_developer` | 写入 EAR token 的 `vid` 字段 |
| `signing_key_path` | EAR/JWT 签名私钥（ES384 / PKCS#8 PEM） |
| `challenge_signing_key_path` | challenge token HMAC 密钥 |
| `challenge_ttl_secs` | challenge token TTL（默认 300 秒） |
| `allow_test_nonce` | 是否允许 RP 通过 `--nonce` 指定固定 nonce |
| `cca_trust_anchors_path` | CCA trust anchors |
| `cca_reference_values_path` | CCA reference values |
| `csv_hsk_cek_dir` | CSV 本地 HSK/CEK 证书目录 |
| `csv_allow_kds_fetch` | 是否允许从 KDS 在线下载 |
| `csv_kds_base_url` | KDS 下载基地址 |
| `appraisal_policy_path` | 可选，appraisal policy 文件路径 |

### `configs/attester.toml`

| 字段 | 含义 |
|------|------|
| `addr` | gRPC 监听地址 |
| `tee` | 当前 attester 服务的 TEE 类型 |
| `verifier_addr` | verifier 的地址 |
| `evidence_source` | `file` / `guest-components-grpc` |
| `aa_endpoint` | guest-components AA gRPC endpoint（仅 gRPC 取证模式生效） |
| `cca_evidence_path` 等 | 各 TEE 的 fixture 文件路径 |

### `configs/relying-party.toml`

| 字段 | 含义 |
|------|------|
| `addr` | attester 的地址 |
| `mode` | 默认模式（passport / background-check） |
| `nonce` | 默认 nonce（留空让 verifier 随机生成） |

## 环境变量覆盖

所有配置都支持环境变量覆盖，例如：

```bash
RATS_EVIDENCE_SOURCE=guest-components-grpc \
RATS_AA_ENDPOINT=http://127.0.0.1:50002 \
cargo run -p attester
```

完整列表见 `*/src/config.rs`。

## 运行示例

### 默认 file-backed fixture

```bash
# Terminal 1
cargo run -p verifier

# Terminal 2
cargo run -p attester

# Terminal 3 — passport 模式
cargo run -p relying-party -- --mode passport
```

### Background-check 模式

```bash
cargo run -p relying-party -- --mode background-check
```

### 固定 nonce 测试

要求 verifier 配置 `allow_test_nonce = true`：

```bash
cargo run -p relying-party -- --mode passport --nonce expected-demo-nonce
```

### CCA fixture 的硬件绑定测试

`test_data/cca/cca-token.cbor` 内已固化 realm challenge，对应的 base64url 形式：

```bash
cargo run -p relying-party -- --mode passport \
  --nonce-b64 V-l5riYY3gwatzFExEDXQc-SNtydUu0ZAFM4Kk0ZAlL58DcEA8NdyxVftDYtc8ZtWwSUv5OTFdPcUrjNyLhalg
```

verifier 用该 nonce 签发 challenge → attester 取证 → verifier 比对 fixture 中的 realm challenge 字节，匹配则签出 `hardware_verified` token。

## guest-components gRPC 取证

在 confidential guest 内：

1. 启动 guest-components Attestation Agent，并暴露 gRPC 服务（默认监听 `0.0.0.0:50002`）。
2. 项目侧切换 `evidence_source`：

```toml
# configs/attester.toml
evidence_source = "guest-components-grpc"
aa_endpoint = "http://127.0.0.1:50002"
```

3. 启动 attester：

```bash
cargo run -p attester
```

4. 发起证明：

```bash
cargo run -p relying-party -- --mode passport
```

attester 会把 verifier 签发的 challenge nonce 作为 `runtime_data` 传给 AA，AA 返回的 evidence 经格式适配后送 verifier：

| TEE | guest-components 字段 → verifier 输入 |
|-----|-------------------------------------|
| CCA | `token` → 原始 CCA token bytes |
| TDX | `quote` → base64 解码后的 raw quote |
| CSV | trustee-style JSON 直接转交 |
| Kunpeng | 不支持 |

## 测试

```bash
cargo fmt --all
cargo test --workspace --all-features
cargo check --workspace --all-targets
```

主要覆盖：

- challenge token 签发 / 校验 / 篡改拒签
- CCA / TDX / CSV / Kunpeng verifier 路径
- challenge / report data 匹配 / 不匹配
- attester 模式分发与 evidence 处理
- guest-components gRPC 取证适配
- relying-party CLI 解析与工作流编排
