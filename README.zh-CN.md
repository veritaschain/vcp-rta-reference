# VCP 参考交易代理 (VCP-RTA)

[English](README.md) | [日本語](README.ja.md) | [**中文**](README.zh-CN.md) | [Español](README.es.md)

![VCP v1.1](https://img.shields.io/badge/VCP-v1.1-blue)
![Tier Silver](https://img.shields.io/badge/Tier-Silver-silver)
![License CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)

> **"验证，不要信任。"**

VCP-RTA 是一个参考实现，展示了算法交易系统的 **VCP v1.1 Silver Tier** 合规性。本仓库提供完整的、可验证的证据包，第三方可以独立验证。

---

## 🆕 v1.1 新特性

| 特性 | v1.0 | v1.1 |
|------|------|------|
| **三层架构** | - | ✅ 新增 |
| **外部锚定（Silver）** | 可选 | **必需** |
| **策略标识** | - | **必需** |
| **PrevHash** | 必需 | 可选 |
| **完整性保证** | - | ✅ 新增 |

> **v1.1 核心增强：** 将防篡改扩展到**完整性保证** — 第三方现在不仅可以验证事件未被更改，还可以验证**没有必需的事件被遗漏**。

---

## ✅ 快速验证

```bash
# 克隆仓库
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference

# 验证链完整性
python tools/verifier/vcp_verifier.py \
    evidence/01_sample_logs/vcp_rta_demo_events.jsonl \
    evidence/04_anchor/public_key.json
```

---

## 🔍 篡改检测演示

```bash
python evidence/03_tamper_demo/tamper_demo.py \
    evidence/01_sample_logs/vcp_rta_demo_events.jsonl
```

---

## ⚠️ 重要免责声明

本仓库仅供**教育和演示目的**。

- ✅ VCP v1.1 Silver Tier 的参考实现
- ✅ 适合学习和集成测试
- ❌ **不是**产品、认证或合规判定
- ❌ **不是**投资建议或交易推荐
- ❌ **不适用于**没有适当密钥管理的生产环境

---

## 📄 许可证

本作品采用 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) 许可。

---

## 📧 联系方式

**VeritasChain 标准组织 (VSO)**  
- 邮箱: standards@veritaschain.org  
- GitHub: [github.com/veritaschain](https://github.com/veritaschain)

---

*"在算法时代编码信任"*
