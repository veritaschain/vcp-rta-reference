# VCP Reference Trading Agent (VCP-RTA)

[![VCP Version](https://img.shields.io/badge/VCP-v1.0-blue)](https://github.com/veritaschain/vcp-spec)
[![Tier](https://img.shields.io/badge/Tier-Silver-silver)](https://github.com/veritaschain/vcp-spec)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-green)](LICENSE)

[English](README.md) | **日本語** | [中文](README.zh-CN.md) | [Español](README.es.md)

**VCP-RTA** は、アルゴリズム取引システム向けのVCP v1.0 Silver Tier準拠を実証する参照実装です。本リポジトリは、第三者が独立して検証可能な完全なエビデンスパックを提供します。

---

## 🎯 目的

この参照実装は以下を実証します：

- **不変の監査証跡**: SHA-256ハッシュチェーンによるイベントログ
- **AIガバナンス透明性**: マルチモデルコンセンサス決定の記録（VCP-GOV）
- **第三者検証可能性**: 誰でもオフラインでチェーンの整合性を検証可能
- **改ざん検知**: 1行の削除で即座に検証失敗

---

## 📦 リポジトリ構成

```
vcp-rta-reference/
├── README.md                    # 英語版README
├── README.ja.md                 # 日本語版README（本ファイル）
├── DISCLAIMER.md                # 免責事項
├── LICENSE                      # CC BY 4.0
├── evidence/
│   ├── 00_raw/                  # 生データ（匿名化済み）
│   ├── 01_sample_logs/          # VCPイベントチェーン（JSONL）
│   ├── 02_verification/         # 検証手順・スクリプト
│   ├── 03_tamper_demo/          # 改ざん検知デモンストレーション
│   ├── 04_anchor/               # マークルルート・タイムスタンプ
│   └── 05_environment/          # 実行環境仕様
├── tools/
│   ├── log_converter/           # 生ログをVCP形式に変換
│   └── verifier/                # チェーン検証ツール
└── docs/
    └── architecture.md          # システムアーキテクチャ
```

---

## 🚀 クイックスタート

### エビデンスパックの検証

```bash
# リポジトリをクローン
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference

# 検証を実行（Python 3.8以上、外部依存なし）
python tools/verifier/vcp_verifier.py evidence/01_sample_logs/vcp_rta_demo_events.jsonl
```

**期待される出力:**
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

### 改ざん検知デモの実行

```bash
cd evidence/03_tamper_demo
python tamper_demo.py
```

これにより、**たった1行を削除するだけで**ハッシュチェーン全体が破壊されることが実証されます。

---

## 📊 エビデンスパック内容

| コンポーネント | 説明 | イベント数 |
|---------------|------|-----------|
| SIG | AIコンセンサスシグナル | 30 |
| ORD | 注文送信 | 30 |
| ACK | ブローカー応答 | 30 |
| EXE | 約定 | 30 |
| CLS | ポジションクローズ | 30 |
| **合計** | | **150** |

### マークルルート

```
e0a1a56c35c63b0ea33754f000ecdc73c1130c2cb9997b5deb728ba1a2ba69b9
```

---

## 🔐 VCP準拠状況

| モジュール | 要件 | ステータス |
|-----------|------|-----------|
| VCP-CORE | UUID v7、タイムスタンプ、ハッシュチェーン | ✅ PASS |
| VCP-TRADE | 注文/約定記録 | ✅ PASS |
| VCP-GOV | AI意思決定の透明性 | ✅ PASS |
| VCP-RISK | リスクパラメータ | ✅ PASS |
| VCP-SEC | SHA-256、Ed25519構造 | ✅ PASS |

---

## 🛡️ セキュリティモデル

### ハッシュチェーン
```
Genesis (PrevHash = 64個のゼロ)
    ↓
Event #1 → EventHash #1
    ↓
Event #2 → EventHash #2 (PrevHash = #1)
    ↓
  ...
    ↓
Event #N → EventHash #N (PrevHash = #N-1)
    ↓
Merkle Root
```

### 改ざん耐性
- **1バイト変更** → ハッシュ不一致 → 検出
- **1行削除** → PrevHash不一致 → 検出
- **イベント並べ替え** → チェーン破損 → 検出

---

## 📋 必要要件

- Python 3.8以上
- 外部依存なし（標準ライブラリのみ）
- オフラインで動作

---

## 📜 ライセンス

本プロジェクトは [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE) の下でライセンスされています。

適切なクレジット表示を行う限り、複製、再配布、改変が可能です。

---

## 🔗 参考資料

- [VCP仕様書 v1.0](https://github.com/veritaschain/vcp-spec)
- [VeritasChain Standards Organization](https://veritaschain.org)
- [RFC 8785 - JSON正規化スキーム](https://tools.ietf.org/html/rfc8785)
- [RFC 6962 - Certificate Transparency](https://tools.ietf.org/html/rfc6962)

---

## 📧 お問い合わせ

- **組織**: VeritasChain Standards Organization (VSO)
- **ウェブサイト**: https://veritaschain.org
- **仕様書**: https://github.com/veritaschain/vcp-spec

---

**信頼するな、検証せよ。**  
**VCP - アルゴリズム取引に真実を確立する**
