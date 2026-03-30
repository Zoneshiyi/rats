# 统一远程认证

## 1. 总体框架

- **Attestation Service（Attester）**：按模式产出 Evidence 或直接产出 Attestation Token
- **Verifier**：验证不同 TEE 的 Evidence，生成并签名 EAR/JWT
- **Relying Party**：通过协议发起认证请求，接收并展示最终认证结果

## 2. 模块分解

### 2.1 protos（协议与消息模型）

职责：定义跨模块通信协议，并生成 Rust 类型。

- 协议定义：`Mode`、`TEE`、`ErrorCode`、`RpcMethod`、`AttestationRequest/Response`、`VerificationRequest/Response`、`RpcRequest/Response`
- 代码生成：`build.rs` 负责 proto -> Rust，并在构建后清洗生成文件，避免内联属性导致编译问题\
  见 protos/build.rs
- 导出方式：`protos/src/lib.rs` 统一 include 并 re-export\
  见 protos/lib.rs

### 2.2 verifier（证据验证与EAR签发）

职责：按 TEE 类型验证 Evidence，输出签名的 EAR/JWT。

- 验证器分发入口：`to_verifier(tee)`\
  见 verifier/lib.rs
- EAR 公共初始化：`init_ear(profile_name)`\
  见 verifier/lib.rs
- CCA 路径关键函数：
  - `init_profile()`：初始化并幂等注册 profile
  - `check_evidence()`：完整性校验 + 参考值比对
  - `gen_ear_token()`：组装 EAR 子模块
  - `verify()`：串联上述步骤并完成签名\
    见 verifier/cca.rs
- TDX 路径关键函数：
  - `init_profile()`：初始化并幂等注册 profile
  - `check_quote()`：解析并校验 quote
  - `gen_ear_token()`：组装 TDX EAR
  - `verify()`：串联验证并签名\
    见 verifier/tdx.rs

### 2.3 attester（服务端与协议处理）

职责：承接 RP 请求，按模式返回 Token 或 Evidence，并提供 verification 接口。

- `Attester` 抽象：定义 `get_evidence(tee, nonce)`\
  见 attestation-service/lib.rs
- `FileBackedAttester`：从配置路径读取证据，nonce 绑定到 `init_data`\
  见 attestation-service/lib.rs
- `AttesterService::attestation_evaluate()`：
  - `MODE_PASSPORT`：直接验证并返回 token
  - `MODE_BACKGROUND_CHECK / MODE_MIX`：返回 evidence\_list\
    见 attestation-service/lib.rs
- `AttesterService::verification_evaluate()`：接收 evidence，调用 verifier 返回 token\
  见 attestation-service/lib.rs
- 启动入口：按 `RATS_TEE` 选择 CCA/TDX，按 `RATS_ATTESTER_ADDR` 或兼容的 `RATS_ATTESTATION_ADDR` 监听\
  见 attestation-service/main.rs

### 2.4 relying-party（命令行依赖方）

职责：通过协议发起认证请求并展示最终结果。

- 参数解析：`--addr --mode --nonce`\
  见 relying-party/main.rs
- 主流程：
  - 发起 `attest(mode, nonce)`
  - 若返回 token 则直接结束
  - 若返回 evidence\_list 则继续调用 `verify(evidence)` 获取最终 token\
    见 relying-party/main.rs
- 结果展示：
  - 打印最终 token
  - 尝试解码 JWT payload 为 JSON 并输出\
    见 relying-party/main.rs

## 3. 关键流程（按模式）

### 3.1 Passport 模式

1. RP 调用 `attest(MODE_PASSPORT, nonce)`
2. Attestation Service 获取本地 evidence
3. Service 内部直接调用 Verifier 验证 evidence
4. 返回最终 attestation token（EAR/JWT）给 RP
5. RP 展示 token 与解码结果

### 3.2 Background-Check / Mix 模式

1. RP 调用 `attest(MODE_BACKGROUND_CHECK|MODE_MIX, nonce)`
2. Attestation Service 返回 `evidence_list`
3. RP 调用 `verify(evidence_list)`
4. Service 调用 Verifier 产出 token
5. RP 展示最终 token 与解码结果

## 4. 模块关系与调用边界

- **protos** 是唯一协议源，其他模块都依赖它的消息类型。
- **relying-party** 不直接依赖 verifier，只通过 **attester** 暴露的协议进行交互。
- **attester** 是编排层：负责模式判断、请求分发、错误码归一化、与 verifier 对接。
- **verifier** 是安全判定与签发层：负责证据真实性/完整性评估与 EAR 签名输出。

**RP 负责发起和消费结果，Service 负责协议编排，Verifier 负责信任判断，Protos 负责统一语言。**
