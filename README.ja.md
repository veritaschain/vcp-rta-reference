# VCP リファレンストレーディングエージェント (VCP-RTA)

[English](README.md) | [**日本語**](README.ja.md)

![VCP v1.1](https://img.shields.io/badge/VCP-v1.1-blue)
![Tier Silver](https://img.shields.io/badge/Tier-Silver-silver)
![License CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)

> **"信頼するな、検証せよ。"**

VCP-RTAは、アルゴリズム取引システムにおける**VCP v1.1 Silverティア**準拠を実証するリファレンス実装です。第三者が独立して検証可能な完全なエビデンスパックを提供します。

**注:** 口座番号、チケットID等の機密情報はプライバシー保護のため匿名化されています。

---

## 🆕 v1.1の新機能

| 機能 | v1.0 | v1.1 |
|------|------|------|
| **三層アーキテクチャ** | - | ✅ 新規 |
| **外部アンカー (Silver)** | 任意 | **必須** |
| **ポリシー識別子** | - | **必須** |
| **PrevHash** | 必須 | 任意 |
| **完全性保証** | - | ✅ 新規 |

---

## 📁 リポジトリ構造

```
vcp_v1_1_repo_aligned/
├── evidence/
│   ├── evidence_index.json
│   ├── 01_trade_logs/
│   │   └── vcp_rta_events.jsonl
│   ├── 02_verification/
│   │   └── verification_report.txt
│   ├── 03_tamper_demo/
│   │   ├── tamper_demo.py
│   │   └── tampered_omission.jsonl
│   └── 04_anchor/
│       ├── security_object.json
│       ├── anchor_reference.json
│       └── public_key.json
├── tools/verifier/
│   └── vcp_verifier.py
├── docs/
│   ├── VERIFICATION_GUIDE.md
│   └── architecture.md
├── README.md / README.ja.md
├── CHANGELOG.md
├── DISCLAIMER.md
└── LICENSE
```

---

## 🚀 クイック検証

```bash
# 検証実行
python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_rta_events.jsonl \
    -s evidence/04_anchor/security_object.json

# 改ざん検知デモ
python evidence/03_tamper_demo/tamper_demo.py
```

---

## 📊 エビデンスサマリー

| 指標 | 値 |
|------|-----|
| **総イベント数** | 40 |
| **シグナルイベント** | 20 |
| **注文イベント** | 20 |
| **期間** | 2025-11-20 〜 2025-11-21 |
| **VCPバージョン** | 1.1 |
| **ティア** | Silver |

---

## 🔐 プライバシー保護

- 口座番号は匿名化（ANON_XXXXXXXX形式）
- チケットIDはソルト付きハッシュ化
- 取引金額は除外
- 個人を特定できる情報は非公開

---

## 📜 ライセンス

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

---

## 🔗 関連リンク

- [VCP仕様書 v1.1](https://github.com/veritaschain/vcp-spec)
