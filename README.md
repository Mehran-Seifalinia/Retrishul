# ReTrishul

[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Extension-orange)](https://portswigger.net/burp)
[![Jython](https://img.shields.io/badge/Jython-2.7-blue)](https://www.jython.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**ReTrishul** is a Burp Suite extension for **active** detection of:
- Cross‑Site Scripting (XSS)
- SQL Injection (SQLi)
- Server‑Side Template Injection (SSTI)

It intercepts in‑scope proxy requests, injects payloads, and analyses responses. Findings appear in a dedicated tab with an interactive issue tree and request/response viewers.

---

## Installation

1. **Download Jython Standalone** (2.7.x) from [jython.org](https://www.jython.org/download)
2. **Burp → Extender → Options** → set Jython location
3. **Burp → Extender → Extensions → Add**  
   - Type: **Python**  
   - File: `Retrishul.py`
4. The **ReTrishul** tab appears. Console shows: `Thank You for Installing ReTrishul`

---

## Usage

### Enable & Scope
- **Config tab** → click `Intercept Off` → toggles to `Intercept On`
- Ensure target is **in scope** (Burp `Target → Scope`)

### Automatic detection
- Any **in‑scope proxy response** with parameters (GET/POST/JSON) is tested

### Manual sending
- Right‑click any request in Proxy, Repeater, etc. → `Send request to ReTrishul`

### Review results
- Main table shows method, URL, parameter count, and status per vulnerability
- **Click a row** → `Issues` tab shows vulnerable parameters
- **Click a parameter node** → Advisory panel with:
  - Issue, severity, confidence
  - Payload & evidence
  - Quick fix
  - Request/Response/Highlighted response tabs

### Toggle modules
- Uncheck `Detect XSS`, `Detect SQLi`, or `Detect SSTI` in Config tab to disable a test

---

## Configuration Options

| Option | Effect |
|--------|--------|
| `Intercept Off/On` | Master switch for automatic proxy interception |
| `Auto Scroll` | Automatically scroll table to newest entry |
| `Detect XSS` | Enable/disable XSS tests |
| `Detect SQLi` | Enable/disable SQLi tests |
| `Detect SSTI` | Enable/disable SSTI tests |

---

## Detection Summary

| Vuln | Payload example | Detection criteria |
|------|----------------|---------------------|
| XSS | `testtest<`, `testtest>`, `\'asd`, `\"asd` | Unencoded symbols reflected → score ≥2 = `Found`, score =1 = `Check` |
| SQLi | `' and (select * from (select(sleep(5)))a)--` | Time delay >3s **or** database error messages → score >3 = `Found`, >2 = `Check` |
| SSTI | `${123*456}`, `<%=123*567%>`, `{{123*678}}`, `{{5*'777'}}` | Expected calculation result (`56088`,`69741`,`83394`,`3885`,`777777777777777`) in response → score ≥2 = `Found`, =1 = `Check` |

> **Score to Verdict:**  
> - `Found` → confirmed vulnerability  
> - `Possible! Check Manually` → weak evidence, needs manual review  
> - `Not Found` → no indicators

---

## Limitations

- **Active testing** – sends additional requests. Do not use without permission.
- **Time‑based SQLi** – fixed 5‑second sleep; network jitter may cause false negatives.
- **SSTI coverage** – only EL, ERB, Twig, Jinja2. Others may be missed.
- **JSON parameters** – only top‑level string values; nested/non‑string values may not be tested.
- **Jython performance** – slower than native Java; keep log size moderate.
- **No CSRF tokens** – not maintained between original and test requests.
