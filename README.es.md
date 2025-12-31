# VCP Reference Trading Agent (VCP-RTA)

[English](README.md) | [日本語](README.ja.md) | [中文](README.zh-CN.md) | [**Español**](README.es.md)

![VCP v1.1](https://img.shields.io/badge/VCP-v1.1-blue)
![Tier Silver](https://img.shields.io/badge/Tier-Silver-silver)
![License CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)

> **"Verificar, no confiar."**

VCP-RTA es una implementación de referencia que demuestra el cumplimiento de **VCP v1.1 Silver Tier** para sistemas de trading algorítmico.

---

## 🆕 Novedades en v1.1

| Característica | v1.0 | v1.1 |
|----------------|------|------|
| **Arquitectura de Tres Capas** | - | ✅ NUEVO |
| **Ancla Externa (Silver)** | OPCIONAL | **REQUERIDO** |
| **Identificación de Política** | - | **REQUERIDO** |
| **PrevHash** | REQUERIDO | OPCIONAL |
| **Garantías de Completitud** | - | ✅ NUEVO |

---

## ✅ Verificación Rápida

```bash
# Clonar repositorio
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference

# Verificar integridad de la cadena
python tools/verifier/vcp_verifier.py \
    evidence/01_sample_logs/vcp_rta_demo_events.jsonl \
    evidence/04_anchor/public_key.json
```

---

## 🔍 Demo de Detección de Manipulación

```bash
python evidence/03_tamper_demo/tamper_demo.py \
    evidence/01_sample_logs/vcp_rta_demo_events.jsonl
```

---

## ⚠️ Aviso Legal Importante

Este repositorio se proporciona **solo con fines educativos y de demostración**.

- ✅ Implementación de referencia de VCP v1.1 Silver Tier
- ✅ Adecuado para aprendizaje y pruebas de integración
- ❌ **NO** es un producto, certificación o determinación de cumplimiento
- ❌ **NO** es asesoramiento de inversión o recomendación de trading

---

## 📄 Licencia

Este trabajo está licenciado bajo [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

## 📧 Contacto

**VeritasChain Standards Organization (VSO)**  
- Email: standards@veritaschain.org  
- GitHub: [github.com/veritaschain](https://github.com/veritaschain)

---

*"Codificando Confianza en la Era Algorítmica"*
