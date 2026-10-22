# VCP リファレンストレーディングエージェント (VCP-RTA)

[English](README.md) | [**日本語**](README.ja.md)

![VCP v1.1](https://img.shields.io/badge/VCP-v1.1-blue)
![Tier Silver](https://img.shields.io/badge/Tier-Silver-silver)
![License CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)

> **"信頼するな、検証せよ。"**

VCP-RTAは、アルゴリズム取引ログの **VCP v1.1** 形式のエビデンスパックです。v1.2 はここでは主張しません。第三者が `tools/verifier/vcp_verifier.py` で Ed25519 署名と公開された Merkle 根を確認できます。OpenTimestamps の外部アンカーは、このリポジトリの公開ファイルからは確認できません。詳細は [evidence/VERIFICATION_STATUS.md](evidence/VERIFICATION_STATUS.md) を参照してください。

**注:** 口座番号、チケットID等の機密情報はプライバシー保護のため匿名化されています。

---

## 🆕 v1.1の新機能

| 機能 | v1.0 | v1.1 |
|------|------|------|
| **三層アーキテクチャ** | - | ✅ 新規 |
| **外部アンカー (Silver)** | 任意 | 参照名のみ。`merkle_root.ots` は公開されていない |
| **ポリシー識別子** | - | **必須** |
| **PrevHash** | 必須 | 任意 |
| **欠落の検査** | - | 公開された Merkle 根を渡したときに比較できる |

---

## 📁 リポジトリ構造

```
vcp_v1_1_repo_aligned/
├── evidence/
│   ├── evidence_index.json          # 説明用。署名の対象ではない
│   ├── VERIFICATION_STATUS.md       # 検証できることとできないこと
│   ├── 01_trade_logs/
│   │   └── vcp_rta_events.jsonl
│   ├── 02_verification/
│   │   ├── verification_report.txt  # 過去の出力。内容は変更しない
│   │   ├── verification_report_2026-10-22.txt  # 現行の検証結果
│   │   └── verification_report_2026-10-22.json
│   ├── 03_tamper_detection/
│   │   ├── tamper_detection_test.py
│   │   └── tampered_chain.jsonl
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

依存: Python 3.8+ と `cryptography`（`python3 -m pip install cryptography`）。未導入のとき署名検査は UNVERIFIABLE です。

```bash
python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_rta_events.jsonl \
    -s evidence/04_anchor/security_object.json \
    -k evidence/04_anchor/public_key.json \
    -a evidence/04_anchor/anchor_reference.json
```

終了コード: `0` VALID、`1` INVALID、`2` UNVERIFIABLE（検証不能）。`--json` で同じ結果を JSON にします。

公開パックでの結果は全体が **UNVERIFIABLE**（終了コード 2）です。Ed25519 署名は **VALID**（40 件）、Merkle 根は公開値 `86c05dbad79ffe6fdb5c3063128df0af0bcb5a3e95f4586348f13ca49778a47e` と **VALID** で一致します。外部アンカーは **UNVERIFIABLE** です。`merkle_root.ots` は公開ファイルにありません。

この Merkle 木は VCP v1.1 の構成（葉に `0x00`、内部ノードに `0x01`、奇数ノードは複製）です。厳密な RFC 6962 §2.1 ではありません。

`tampered_chain.jsonl` を同じ `-s` と `-k` で検証すると **INVALID**（終了コード 1）です。

`evidence/02_verification/verification_report.txt` は過去の生成出力で、バイト列はそのまま残しています。そこに書かれた “Fully Compliant” という文言は現行ではなく、後継の結果に置き換えられています。現在の結果は [`evidence/02_verification/verification_report_2026-10-22.txt`](evidence/02_verification/verification_report_2026-10-22.txt) です（JSON は [`verification_report_2026-10-22.json`](evidence/02_verification/verification_report_2026-10-22.json)）。

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

- チケットIDはSHA-256ハッシュ化
- ポジションIDはSHA-256ハッシュ化
- 取引金額は除外
- 口座識別情報は除外
- AIモデル名は除外（投票数のみ記録）

---

## 📜 ライセンス

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

---

## 🔗 関連リンク

- [VCP仕様書 v1.1](https://github.com/veritaschain/vcp-spec)
