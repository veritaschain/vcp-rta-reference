> **ステータス訂正 — 2026年10月25日**
>
> - 本リポジトリは、VeritasChain Standards Organization（VSO）を運営する VeritasChain株式会社によるファーストパーティの PoC（概念実証）コードです。対象は VCP v1.1（Silver ティア）です。VCP v1.1 にはタグ付きリリースがなく、VCP v1.2（Released、タグ `v1.2.0`）に置き換えられています。
> - いずれの VCP ティアへの適合も、VAP への適合も、独立に確立されていません。VAP およびそのプロファイル（VCP を含む）の外部実装は現時点でゼロです。
> - 認証は受けていません。VSO は認証を直接発行しません。認証スキームは、スキームオーナーから独立した適合性評価機関（CAB）を要件としていますが、登録済みの唯一の CAB である VeritasChain株式会社は独立していません（VAP v1.2 ERRATA E-2026-10-21）。
> - 既知の制約：`evidence/04_anchor/anchor_reference.json` が参照する OpenTimestamps 証明ファイル（`merkle_root.ots`）は本リポジトリに含まれていないため、アンカーをリポジトリから確認できません。`tools/verifier/vcp_verifier.py` は Ed25519 署名も OpenTimestamps 証明も検証しません。Merkle 構築は奇数個のレベルで末尾ノードを複製します（RFC 6962 のハッシュ接頭辞は使っていますが、RFC 6962 の木構築アルゴリズムではありません）。
> - エビデンスパック（`evidence/`）内の文言（`verification_report.txt` や `evidence_index.json` の "Fully Compliant" など）は本訂正より前のもので、変更していません。結果ではなく設計目標として読んでください。

# VCP リファレンストレーディングエージェント (VCP-RTA)

[English](README.md) | [**日本語**](README.ja.md)

![VCP v1.1](https://img.shields.io/badge/VCP-v1.1-blue)
![Non-certified PoC](https://img.shields.io/badge/Status-Non--certified_PoC-orange)
![License CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)

> **"信頼するな、検証せよ。"**

VCP-RTAは、**VCP v1.1 Silverティア**を目標とするアルゴリズム取引監査証跡の PoC です。Silver 適合は確立されていません。第三者がハッシュ・連番・Merkle root の確認を再現できるエビデンスパックを提供します（確認されない項目は上記のステータス訂正を参照）。

**注:** 口座番号、チケットID等の機密情報はプライバシー保護のため匿名化されています。

---

## 🆕 v1.1の新機能

| 機能 | v1.0 | v1.1 |
|------|------|------|
| **三層アーキテクチャ** | - | ✅ 新規 |
| **外部アンカー (Silver)** | 任意 | **必須** |
| **ポリシー識別子** | - | **必須** |
| **PrevHash** | 必須 | 任意 |
| **完全性（欠落検知）** | - | ✅ 新規 |

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

```bash
# 検証実行
python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_rta_events.jsonl \
    -s evidence/04_anchor/security_object.json

# 改ざん検知テスト
python evidence/03_tamper_detection/tamper_detection_test.py
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
| **目標ティア** | Silver（未確立） |

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
