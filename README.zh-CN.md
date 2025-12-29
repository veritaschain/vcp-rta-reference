# VCP 参考交易代理 (VCP-RTA)

[![VCP Version](https://img.shields.io/badge/VCP-v1.0-blue)](https://github.com/veritaschain/vcp-spec)
[![Tier](https://img.shields.io/badge/Tier-Silver-silver)](https://github.com/veritaschain/vcp-spec)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-green)](LICENSE)

[English](README.md) | [日本語](README.ja.md) | **中文** | [Español](README.es.md)

**VCP-RTA** 是一个参考实现，展示算法交易系统如何符合 VCP v1.0 Silver Tier 规范。本仓库提供完整的、可由第三方独立验证的证据包。

---

## 🎯 目的

本参考实现演示：

- **不可变审计追踪**: SHA-256 哈希链事件日志
- **AI 治理透明度**: 多模型共识决策记录 (VCP-GOV)
- **第三方可验证性**: 任何人都可以离线验证链的完整性
- **篡改检测**: 删除一行即可立即破坏验证

---

## 📦 仓库结构

```
vcp-rta-reference/
├── README.md                    # 英文 README
├── README.zh-CN.md              # 中文 README（本文件）
├── DISCLAIMER.md                # 免责声明
├── LICENSE                      # CC BY 4.0
├── evidence/
│   ├── 00_raw/                  # 原始数据（已匿名化）
│   ├── 01_sample_logs/          # VCP 事件链 (JSONL)
│   ├── 02_verification/         # 验证程序和脚本
│   ├── 03_tamper_demo/          # 篡改检测演示
│   ├── 04_anchor/               # 默克尔根和时间戳
│   └── 05_environment/          # 执行环境规格
├── tools/
│   ├── log_converter/           # 将原始日志转换为 VCP 格式
│   └── verifier/                # 链验证工具
└── docs/
    └── architecture.md          # 系统架构
```

---

## 🚀 快速开始

### 验证证据包

```bash
# 克隆仓库
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference

# 运行验证（Python 3.8+，无需外部依赖）
python tools/verifier/vcp_verifier.py evidence/01_sample_logs/vcp_rta_demo_events.jsonl
```

**预期输出：**
```
============================================================
VCP Chain Verification Report
============================================================
File: vcp_rta_demo_events.jsonl
Total Events: 150
Unique TraceIDs: 30

Verification Results:
  Genesis: PASS
  Hash Chain: PASS
  Timestamp Monotonicity: PASS

============================================================
VERIFICATION: PASS - Chain integrity verified
============================================================

Merkle Root: e0a1a56c35c63b0ea33754f000ecdc73c1130c2cb9997b5deb728ba1a2ba69b9
```

### 运行篡改检测演示

```bash
cd evidence/03_tamper_demo
python tamper_demo.py
```

这将演示**仅删除一行**就会破坏整个哈希链。

---

## 📊 证据包内容

| 组件 | 描述 | 事件数 |
|------|------|--------|
| SIG | AI 共识信号 | 30 |
| ORD | 订单提交 | 30 |
| ACK | 经纪商确认 | 30 |
| EXE | 执行 | 30 |
| CLS | 平仓 | 30 |
| **总计** | | **150** |

### 默克尔根

```
e0a1a56c35c63b0ea33754f000ecdc73c1130c2cb9997b5deb728ba1a2ba69b9
```

---

## 🔐 VCP 合规状态

| 模块 | 要求 | 状态 |
|------|------|------|
| VCP-CORE | UUID v7、时间戳、哈希链 | ✅ 通过 |
| VCP-TRADE | 订单/执行记录 | ✅ 通过 |
| VCP-GOV | AI 决策透明度 | ✅ 通过 |
| VCP-RISK | 风险参数 | ✅ 通过 |
| VCP-SEC | SHA-256、Ed25519 结构 | ✅ 通过 |

---

## 🛡️ 安全模型

### 哈希链
```
创世块 (PrevHash = 64 个零)
    ↓
Event #1 → EventHash #1
    ↓
Event #2 → EventHash #2 (PrevHash = #1)
    ↓
  ...
    ↓
Event #N → EventHash #N (PrevHash = #N-1)
    ↓
默克尔根
```

### 防篡改性
- **更改 1 字节** → 哈希不匹配 → 检测到
- **删除 1 行** → PrevHash 不匹配 → 检测到
- **重新排序事件** → 链断裂 → 检测到

---

## 📋 系统要求

- Python 3.8 或更高版本
- 无外部依赖（仅标准库）
- 支持离线运行

---

## 📜 许可证

本项目采用 [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE) 许可证。

只要提供适当的署名，您可以复制、再分发或修改本作品。

---

## 🔗 参考资料

- [VCP 规范 v1.0](https://github.com/veritaschain/vcp-spec)
- [VeritasChain 标准组织](https://veritaschain.org)
- [RFC 8785 - JSON 规范化方案](https://tools.ietf.org/html/rfc8785)
- [RFC 6962 - 证书透明度](https://tools.ietf.org/html/rfc6962)

---

## 📧 联系方式

- **组织**: VeritasChain Standards Organization (VSO)
- **网站**: https://veritaschain.org
- **规范**: https://github.com/veritaschain/vcp-spec

---

**不要信任，要验证。**  
**VCP - 为算法交易建立真相**
