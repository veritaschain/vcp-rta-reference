# VCP Reference Trading Agent (VCP-RTA)

[![VCP Version](https://img.shields.io/badge/VCP-v1.0-blue)](https://github.com/veritaschain/vcp-spec)
[![Tier](https://img.shields.io/badge/Tier-Silver-silver)](https://github.com/veritaschain/vcp-spec)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-green)](LICENSE)

[English](README.md) | [日本語](README.ja.md) | [中文](README.zh-CN.md) | **Español**

**VCP-RTA** es una implementación de referencia que demuestra el cumplimiento del nivel Silver de VCP v1.0 para sistemas de trading algorítmico. Este repositorio proporciona un paquete de evidencia completo que terceros pueden validar de forma independiente.

---

## 🎯 Propósito

Esta implementación de referencia demuestra:

- **Registro de Auditoría Inmutable**: Registros de eventos encadenados con SHA-256
- **Transparencia en Gobernanza de IA**: Registro de decisiones de consenso multi-modelo (VCP-GOV)
- **Verificabilidad por Terceros**: Cualquiera puede verificar la integridad de la cadena sin conexión
- **Evidencia de Manipulación**: La eliminación de una sola línea rompe inmediatamente la verificación

---

## 📦 Estructura del Repositorio

```
vcp-rta-reference/
├── README.md                    # README en inglés
├── README.es.md                 # README en español (este archivo)
├── DISCLAIMER.md                # Descargo de responsabilidad
├── LICENSE                      # CC BY 4.0
├── evidence/
│   ├── 00_raw/                  # Datos fuente (anonimizados)
│   ├── 01_sample_logs/          # Cadena de eventos VCP (JSONL)
│   ├── 02_verification/         # Procedimientos y scripts de verificación
│   ├── 03_tamper_demo/          # Demostración de detección de manipulación
│   ├── 04_anchor/               # Raíz de Merkle y marcas de tiempo
│   └── 05_environment/          # Especificaciones del entorno de ejecución
├── tools/
│   ├── log_converter/           # Convertir registros a formato VCP
│   └── verifier/                # Herramienta de verificación de cadena
└── docs/
    └── architecture.md          # Arquitectura del sistema
```

---

## 🚀 Inicio Rápido

### Verificar el Paquete de Evidencia

```bash
# Clonar el repositorio
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference

# Ejecutar verificación (Python 3.8+, sin dependencias externas)
python tools/verifier/vcp_verifier.py evidence/01_sample_logs/vcp_rta_demo_events.jsonl
```

**Salida Esperada:**
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

### Ejecutar Demostración de Detección de Manipulación

```bash
cd evidence/03_tamper_demo
python tamper_demo.py
```

Esto demuestra que eliminar **solo una línea** rompe toda la cadena de hash.

---

## 📊 Contenido del Paquete de Evidencia

| Componente | Descripción | Eventos |
|------------|-------------|---------|
| SIG | Señal de Consenso de IA | 30 |
| ORD | Envío de Orden | 30 |
| ACK | Confirmación del Broker | 30 |
| EXE | Ejecución | 30 |
| CLS | Cierre de Posición | 30 |
| **Total** | | **150** |

### Raíz de Merkle

```
e0a1a56c35c63b0ea33754f000ecdc73c1130c2cb9997b5deb728ba1a2ba69b9
```

---

## 🔐 Cumplimiento VCP

| Módulo | Requisito | Estado |
|--------|-----------|--------|
| VCP-CORE | UUID v7, Marcas de tiempo, Cadena de Hash | ✅ APROBADO |
| VCP-TRADE | Registro de Órdenes/Ejecuciones | ✅ APROBADO |
| VCP-GOV | Transparencia en Decisiones de IA | ✅ APROBADO |
| VCP-RISK | Parámetros de Riesgo | ✅ APROBADO |
| VCP-SEC | Estructura SHA-256, Ed25519 | ✅ APROBADO |

---

## 🛡️ Modelo de Seguridad

### Cadena de Hash
```
Génesis (PrevHash = 64 ceros)
    ↓
Evento #1 → EventHash #1
    ↓
Evento #2 → EventHash #2 (PrevHash = #1)
    ↓
  ...
    ↓
Evento #N → EventHash #N (PrevHash = #N-1)
    ↓
Raíz de Merkle
```

### Resistencia a Manipulación
- **1 byte modificado** → Hash no coincide → Detectado
- **1 línea eliminada** → PrevHash no coincide → Detectado
- **Eventos reordenados** → Cadena rota → Detectado

---

## 📋 Requisitos

- Python 3.8 o superior
- Sin dependencias externas (solo biblioteca estándar)
- Funciona sin conexión

---

## 📜 Licencia

Este trabajo está licenciado bajo [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE).

Puede copiar, redistribuir o adaptar este trabajo siempre que proporcione la atribución adecuada.

---

## 🔗 Referencias

- [Especificación VCP v1.0](https://github.com/veritaschain/vcp-spec)
- [VeritasChain Standards Organization](https://veritaschain.org)
- [RFC 8785 - Esquema de Canonicalización JSON](https://tools.ietf.org/html/rfc8785)
- [RFC 6962 - Transparencia de Certificados](https://tools.ietf.org/html/rfc6962)

---

## 📧 Contacto

- **Organización**: VeritasChain Standards Organization (VSO)
- **Sitio Web**: https://veritaschain.org
- **Especificación**: https://github.com/veritaschain/vcp-spec

---

**No Confíes, Verifica.**  
**VCP - Estableciendo la Verdad en el Trading Algorítmico**
