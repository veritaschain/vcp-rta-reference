# Execution Environment Specification

**Document ID:** ENV-2025-001  
**Version:** 1.0  
**Date:** 2025-12-29  

---

## 1. System Environment

### Operating System

| Item | Value |
|------|-------|
| OS | Windows 11 Pro |
| Build | 22H2 (Build 22621.xxx) |
| Architecture | x64 |
| Language | English/Japanese |

### Trading Platform

| Item | Value |
|------|-------|
| Platform | MetaTrader 5 |
| Build Number | 4750+ |
| Broker | Demo Account |
| Server | Demo Server |
| Account Currency | JPY |

### VCP-RTA System

| Item | Value |
|------|-------|
| System Name | VCP Reference Trading Agent |
| Abbreviation | VCP-RTA |
| Version | 1.0.0 |
| Target Symbol | USDJPY |
| Magic Number | 20231120 |

---

## 2. Python Environment

```
Python 3.11.x
pip packages:
  - openai (GPT API)
  - anthropic (Claude API)
  - google-generativeai (Gemini API)
  - requests (Perplexity/Grok API)
```

---

## 3. Data Acquisition Path

### MT5 Side

```
MQL5/Files/_VCP_RTA/
├── signallogs/              <- Signal JSON (by date)
│   └── YYYY-MM-DD/
│       └── signal_*.json
├── trade_history_logs/      <- Trade history CSV
│   └── trade_log_YYYYMMDD.csv
├── positions.json           <- Position state
├── prompt.json              <- AI prompt config
└── config.json              <- System config
```

### Python Side

```python
# signal_*.json structure
{
  "signal_id": "20251118_022757_BUY",
  "datetime": "2025-11-18T02:27:57",
  "final_direction": "BUY",
  "final_confidence": 0.779,
  "gemini_dir": "BUY", "gemini_conf": 0.85,
  "gpt_dir": "BUY", "gpt_conf": 0.70,
  "claude_dir": "BUY", "claude_conf": 0.85,
  "grok_dir": "SELL", "grok_conf": 0.75,
  "pplx_dir": "BUY", "pplx_conf": 0.80,
  "execution": {
    "status": "SUCCESS",
    "ticket": 32925461,
    "position_id": 32925461
  }
}
```

---

## 4. VCP-GOV Related

### Model Hash Acquisition

```python
import hashlib
import json

# Hash of prompt.json
with open("prompt.json", "rb") as f:
    prompt_hash = hashlib.sha256(f.read()).hexdigest()
```

### AI Models Used

| Model | API | Version |
|-------|-----|---------|
| Gemini | Google AI | gemini-2.0-flash-thinking-exp |
| GPT | OpenAI | o3-mini |
| Claude | Anthropic | claude-3-5-sonnet |
| Grok | xAI | grok-2-latest |
| Perplexity | Perplexity | llama-3.1-sonar-large |

---

## 5. Clock Synchronization

### ClockSyncStatus

| Status | Description |
|--------|-------------|
| `BEST_EFFORT` | No NTP sync, using system clock (Silver Tier compliant) |
| `NTP_SYNCED` | NTP synchronized (future support) |

### Timestamp Precision

- **TimestampPrecision:** MILLISECOND
- **Timezone:** UTC (internal processing)
- **Display:** Local timezone

---

## 6. Venue Information

### Demo Venue

| Item | Value |
|------|-------|
| Venue Name | Demo Venue |
| MIC Code | XDMO |
| VenueID | VENUE_DEMO |
| Symbol Format | USDJPY |
| Minimum Lot | 0.01 (1,000 units) |
| Spread | Variable (typically 0.3-2.0 pips) |

---

## 7. Network

### API Connections

| Service | Endpoint | Rate Limit |
|---------|----------|------------|
| OpenAI | api.openai.com | 60 RPM |
| Anthropic | api.anthropic.com | 60 RPM |
| Google AI | generativelanguage.googleapis.com | 60 RPM |
| xAI | api.x.ai | 60 RPM |
| Perplexity | api.perplexity.ai | 20 RPM |

---

## 8. Reproduction Steps

### Environment Setup

```bash
# 1. Python environment
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt

# 2. Install MT5
# Download and install MT5 from broker

# 3. Deploy EA
# Place main.mq5 in MQL5/Experts/
# Place *.mqh in MQL5/Include/

# 4. Compile
# Compile in MetaEditor

# 5. Run
# Execute main.py
# Attach EA to chart in MT5
```

---

## 9. Security

### Handling Confidential Information

| Information | Protection Method |
|-------------|-------------------|
| API Keys | Environment variables / .env (Git excluded) |
| Account ID | Pseudonymized with SHA-256 hash |
| Trade Logs | Local storage only |

### Git Exclusion

```gitignore
.env
*.pem
vcp/keys/
positions.json
```

---

## 10. Contact

| Item | Value |
|------|-------|
| Developer | Anonymous Early Adopter |
| VCP Specification | https://github.com/veritaschain/vcp-spec |
| VSO | https://veritaschain.org |

---

**VCP Reference Trading Agent (VCP-RTA) - VCP v1.0 Silver Tier Implementation**
