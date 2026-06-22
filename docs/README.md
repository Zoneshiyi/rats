# 文档说明

## 阅读顺序

1. [架构与三层分离](architecture.md)：四个 crate 的职责拆分、verifier / attester / relying-party 各自的 Core / Service / API 三层结构
2. [协议](protocol.md)：gRPC 服务清单、challenge token / Mode / Tee / EvidenceSource / ErrorCode 取值语义，以及 passport / background-check 时序
3. [TEE 状态详解](tee-status.md)：CCA / CSV / TDX / Kunpeng 四种 TEE 的当前实现完成度与 `rats.challenge_binding` 取值含义
4. [运行与配置](running.md)：默认端口、三份 toml 配置项、环境变量覆盖、CCA fixture 的硬件绑定测试、guest-components gRPC 切换方式

## 文档与代码的对齐原则

- 文档描述与代码冲突时以代码为准
- 配置文件字段 / 取值变更应同步修改 `docs/running.md`
- challenge token 编码 / EAR 字段语义变更应同步修改 `docs/protocol.md`
- 新增 TEE 平台或 binding 状态语义变更应同步修改 `docs/tee-status.md`

## 与 rats-hydra/ 项目的关系

`rats-hydra/` 是另一条独立技术线——基于 hydra 零知识证明的 self-verifying remote attestation，与本项目目录平级但代码独立。两者的关系：

- 本项目（rats/）：硬件 TEE 验证路径，verifier 内置 CCA / CSV / TDX 等平台特定解析器
- rats-hydra/：wasm 组件 + Groth16 路径，verifier 不内置平台代码

设计模式（challenge-first、EAR、replay guard、AppraisalPolicy）相互借鉴但代码独立演进。