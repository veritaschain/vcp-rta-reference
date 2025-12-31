# VCP Reference Trading Agent (VCP-RTA)

[English](README.md) | [**日本語**](README.ja.md) | [中文](README.zh-CN.md) | [Español](README.es.md)

![VCP v1.1](https://img.shields.io/badge/VCP-v1.1-blue)
![Tier Silver](https://img.shields.io/badge/Tier-Silver-silver)
![License CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)

> **「信頼するな、検証せよ。」**

VCP-RTAは、アルゴリズム取引システムにおける**VCP v1.1 Silver Tier**準拠を実証するリファレンス実装です。本リポジトリは、第三者が独立して検証可能な完全なエビデンスパックを提供します。

---

## 🆕 v1.1の新機能

| 機能 | v1.0 | v1.1 |
|------|------|------|
| **三層アーキテクチャ** | - | ✅ 新規 |
| **外部アンカー（Silver）** | 任意 | **必須** |
| **ポリシー識別子** | - | **必須** |
| **PrevHash** | 必須 | 任意 |
| **完全性保証** | - | ✅ 新規 |

> **v1.1の核心的強化:** 改ざん検知を**完全性保証**まで拡張 — 第三者は、イベントが改ざんされていないことだけでなく、**必要なイベントが省略されていないこと**も暗号学的に検証できます。

---

## 🎯 目的

本リファレンス実装は以下を実証します：

- **三層整合性アーキテクチャ**
  - Layer 1: イベント整合性（EventHash, PrevHash）
  - Layer 2: コレクション整合性（Merkleツリー、RFC 6962）
  - Layer 3: 外部検証可能性（署名、アンカー）
- マルチティア展開のための**ポリシー識別子**
- OpenTimestampsによる**外部アンカリング**（v1.1で全ティア必須）
- 全イベントへの**Ed25519デジタル署名**
- マルチモデル投票による**AIコンセンサス記録**（VCP-GOV）

---

## 📁 リポジトリ構成

```
vcp-rta-reference/
├── README.md                    # 英語版
├── README.ja.md                 # 本ファイル
├── README.zh-CN.md              # 中国語版
├── README.es.md                 # スペイン語版
├── CHANGELOG.md                 # バージョン履歴
├── DISCLAIMER.md                # 免責事項
├── LICENSE                      # CC BY 4.0
│
├── docs/
│   ├── architecture.md          # 三層アーキテクチャ（v1.1）
│   ├── VERIFICATION_GUIDE.md    # 検証ガイド
│   └── MIGRATION_v1.0_to_v1.1.md    # 移行ガイド
│
├── evidence/
│   ├── 00_raw/                  # 生シグナルデータ（保持）
│   ├── 01_sample_logs/
│   │   └── vcp_rta_demo_events.jsonl    # 150件の署名済みイベント
│   ├── 02_verification/
│   │   └── verification_report.txt       # 検証結果
│   ├── 03_tamper_demo/
│   │   ├── tamper_demo.py               # 改ざん検知デモ
│   │   └── tamper_demo_output.txt       # デモ結果
│   ├── 04_anchor/
│   │   ├── merkle_root.txt              # Merkle Root
│   │   ├── anchor_record.json           # 外部アンカーレコード
│   │   └── public_key.json              # Ed25519公開鍵
│   ├── 05_environment/          # 環境情報（保持）
│   └── evidence_index.json      # エビデンス目録
│
└── tools/
    └── verifier/
        └── vcp_verifier.py              # 依存なし検証ツール
```

---

## 🔐 三層アーキテクチャ（v1.1）

```
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 3: 外部検証可能性                                            │
│  ├─ デジタル署名（Ed25519）: 必須                                   │
│  ├─ タイムスタンプ（二重形式）: 必須                                │
│  └─ 外部アンカー: 必須（Silverは24時間）                           │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 2: コレクション整合性    ← 完全性保証の核心                  │
│  ├─ Merkleツリー（RFC 6962）: 必須                                 │
│  ├─ Merkle Root: 必須                                              │
│  └─ 監査パス: 必須                                                 │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 1: イベント整合性                                            │
│  ├─ EventHash（SHA-256）: 必須                                     │
│  └─ PrevHash（ハッシュチェーン）: 任意                              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ✅ クイック検証

### 前提条件

- Python 3.8以上（標準ライブラリのみ）
- 外部依存なし

### 検証の実行

```bash
# リポジトリをクローン
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference

# チェーン整合性を検証
python tools/verifier/vcp_verifier.py \
    evidence/01_sample_logs/vcp_rta_demo_events.jsonl \
    evidence/04_anchor/public_key.json
```

### 期待される出力

```
======================================================================
VCP v1.1 Chain Verification Report
======================================================================
File: evidence/01_sample_logs/vcp_rta_demo_events.jsonl
VCP Version: 1.1
Total Events: 150
Unique TraceIDs: 30

Event Types:
  SIG: 30    ORD: 30    ACK: 30    EXE: 30    CLS: 30

Three-Layer Verification Results:
  [Layer 1: Event Integrity]
    Genesis: PASS
    Event Hashes: PASS
    Hash Chain: PASS

  [Layer 2: Collection Integrity]
    Merkle Root: PASS

  [Layer 3: External Verifiability]
    Timestamp Monotonicity: PASS
    Policy Identification: PASS
    Anchor Reference: PASS
    Signatures: PASS (150/150 valid)

======================================================================
VERIFICATION: PASS - VCP v1.1 Chain integrity verified
======================================================================
```

---

## 🔍 改ざん検知デモ

1件のイベントを削除しても即座に検知されることを実証：

```bash
python evidence/03_tamper_demo/tamper_demo.py \
    evidence/01_sample_logs/vcp_rta_demo_events.jsonl
```

---

## 🔄 v1.0からの移行

詳細は[MIGRATION_v1.0_to_v1.1.md](docs/MIGRATION_v1.0_to_v1.1.md)を参照してください。

**クイックサマリー:**

| v1.0 → v1.1 変更 | 対応 |
|------------------|------|
| ポリシー識別子追加 | 全イベントに追加 |
| 外部アンカー追加 | 日次アンカリング実装 |
| SecurityにMerkleRoot追加 | 全イベントに追加 |
| AnchorReference追加 | 全イベントに追加 |
| PrevHash | 任意に（維持または削除可） |

**猶予期間:**
- ポリシー識別子: 2026年3月25日
- 外部アンカー（Silver）: 2026年6月25日

---

## ⚠️ 重要な免責事項

本リポジトリは**教育およびデモンストレーション目的のみ**で提供されています。

- ✅ VCP v1.1 Silver Tierのリファレンス実装
- ✅ 学習および統合テストに適切
- ❌ 製品、認証、またはコンプライアンス判定では**ありません**
- ❌ 投資アドバイスや取引推奨では**ありません**
- ❌ 適切な鍵管理なしの本番利用は**想定していません**

完全な法的通知は[DISCLAIMER.md](DISCLAIMER.md)を参照してください。

---

## 📚 関連リソース

| リソース | リンク |
|----------|--------|
| VCP仕様書 | [github.com/veritaschain/vcp-spec](https://github.com/veritaschain/vcp-spec) |
| VCP Explorer | [explorer.veritaschain.org](https://explorer.veritaschain.org) |
| ドキュメント | [docs.veritaschain.org](https://docs.veritaschain.org) |
| ウェブサイト | [veritaschain.org](https://veritaschain.org) |

---

## 📄 ライセンス

本作品は[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)の下でライセンスされています。

---

## 📧 お問い合わせ

**VeritasChain Standards Organization (VSO)**  
- Email: standards@veritaschain.org  
- GitHub: [github.com/veritaschain](https://github.com/veritaschain)  
- サポート: support@veritaschain.org

---

*「アルゴリズム時代に信頼を刻む」*
