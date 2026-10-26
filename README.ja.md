# VeritasChain Protocol（VCP）リファレンストレーディングエージェント

[English](README.md) | [日本語](README.ja.md)

![Legacy format](https://img.shields.io/badge/Evidence-legacy_v1.1-blue)
![Non-certified PoC](https://img.shields.io/badge/Status-Non--certified_PoC-orange)
![License](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey)

VeritasChain株式会社が運営する **VeritasChain Standards Organization（VSO）** の
ファーストパーティPoCと、過去の取引記録を公開するリポジトリです。
当初の設計目標はVCP v1.1 Silverでしたが、**VCPの各ティア・VAPへの適合、認証、
本番運用への適性、独立第三者による再現は、本リポジトリによって確立していません。**
記録はv1.1を名乗っていますが、参照規格と異なる旧実装固有の符号化を含みます。

## 現在の状態：2026年10月26日

通常の検証器は、利用者が明示的に信頼した公開鍵を指定すると、Ed25519署名を
実際に検証します。各検査を `VALID`・`INVALID`・`INDETERMINATE` で報告し、
材料不足を合格にしたり、別の検査で検出できる不一致を隠したりしません。
通常CLIには外部アンカー検証機能とバッチメタデータ認証はありません。
[現行動作と移行上の注意](tools/verifier/README.md)を参照してください。

**別の追加検証コマンド**では、署名付き補助記録とRFC 3161タイムスタンプを検証できます。
鍵・CA証明書・TSAポリシーは利用者が別途指定します。これは実装拡張であり、VCP/VAPの
正式採択済み形式ではありません。後から取得した補助タイムスタンプを、過去のログ作成時刻や
元のアンカー時刻の証明と扱いません。[追加検証の説明](tools/verifier/SUPPLEMENTAL.md)。

元のアンカー参照に記された `merkle_root.ots` は証拠ディレクトリに含まれていません。
作成者の「確認済み」という記載だけでは、外部アンカーの確認になりません。
`evidence/` 内の過去のレポート・署名・鍵・ログは保存しており、旧「全項目合格」や
「準拠」の記載を現在の検証結果として扱いません。

## 公開40件の再検証

[読み取り専用の再実行手順と記録](tools/verifier/HISTORICAL.md)を追加しました。
2026年10月26日の初回CI再実行では、次の結果が得られています。

| 確認項目 | 結果と範囲 |
| --- | --- |
| 40件すべてのイベントハッシュ | 旧実装のJSON連結形式で一致。JCS適合を意味しません |
| 40件すべてのイベント署名 | 明示的に選択した公開参照鍵と一致。鍵の所有者の身元確認ではありません |
| Merkleルートの署名・全包含経路 | 旧実装の奇数ノード複製方式で一致。厳密なRFC 6962の木ではありません |
| 連番・件数と範囲のローカル比較 | 一致。ただしルートだけの署名は件数・範囲・ポリシーを認証しません |
| 先頭のPrevHash境界・メタデータ認証・元の外部アンカー | 未検証のまま |
| 総合結果 | **INDETERMINATE（未検証項目あり）** |

実際の内訳は **SIG 20件・EXE 20件** です。EXEは約定であり、以前の「注文イベント」
という表記を訂正しました。テストの成功は、この期待結果を再現できたという意味で、
証拠全体を完全合格にしたことではありません。

## 固定版を使った第三者向け再現手順

[2026年10月26日の固定版再現手順](docs/REPRODUCTION_CHECKPOINT_2026-10-26.md)、
[機械可読の照合用JSON](docs/REPRODUCTION_CHECKPOINT_2026-10-26.json)、
[実行者用の報告様式](docs/REVIEWER_REPORT_TEMPLATE.md)を用意しています。
対象は `cc695fe1698250878fbbc5f0c5461591ac8e0954` に固定し、記録された自社CIでは
各環境で回帰809件・公開証拠15件が成功しました。この件数はそのコミットに対する
記録であり、将来のmainの件数を自動保証しません。**独立第三者による再現は未成立**です。
新しいリリースや、既存の固定研究キットの差し替えではありません。

公開手順の通し実行結果は[PR #16の主要結果原本](docs/reproduction-results/2026-10-26-pr16/README.md)に
保存しています。自社CIの原本の一部を選択保存したもので、全ログの恒久保存や
独立第三者による再現を示すものではありません。

## 実行方法

CIはPython 3.11と3.13.5、Ubuntu 24.04で実行します。
[依存関係と再現手順](tools/verifier/REPRODUCING.md)も確認してください。

```sh
python -m pip install -r requirements-verifier-test.txt
python tools/verifier/vcp_verifier.py evidence/01_trade_logs/vcp_rta_events.jsonl \
  -s evidence/04_anchor/security_object.json --json

# 公開参照鍵との数学的な比較を明示的に選択。身元や信頼を確立する操作ではありません。
python tools/verifier/inspect_historical_pack.py --compare-reference-key
```

現在の再検証コマンドは、総合結果が未検証なので **終了コード2** を返します。
通常検証器の `--public-key` は、証拠ファイルとは別の手段で信頼を確立した鍵に使用します。
埋め込まれた公開鍵を自動で信頼しません。

```sh
# 登録済みの回帰テスト。件数は使用する版のランナーを参照
python tools/verifier/run_regression.py
# 公開記録を用いた回帰テスト15件
python -m pytest -q tests/test_historical_evidence.py
```

現在のテストは `tests/` にあります。`evidence/` 内の旧テストスクリプトは歴史資料として
保存しており、現在の成功判定の根拠には使いません。再実行で証拠原本を書き換えません。

## 資料と関連実装

[検証ガイド](docs/VERIFICATION_GUIDE.md)、[実装の構成と限界](docs/architecture.md)、
[過去の統合サンプル](examples/ai-trading-integration/)、
[別リポジトリの新SDK](https://github.com/veritaschain/vcp-sdk)を参照してください。
プラットフォーム別の関連リポジトリは[英語README](README.md#related-implementations-and-historical-materials)にあります。
これらの関連実装は今回の40件の再検証対象ではありません。

[過去の「World's First」調査資料](VCP_Worlds_First_Evidence_Report.pdf)は保存していますが、
今回その先行性主張を検証済みとして採用してはいません。仕様の現行状態は
[VCP仕様リポジトリ](https://github.com/veritaschain/vcp-spec)で確認してください。

[CC BY 4.0](LICENSE)。[免責事項](DISCLAIMER.md)。技術窓口：standards@veritaschain.org。
