# HTTP Attack Log Classification Methodology

This document describes the methodology for classifying HTTP traffic logs into attack categories using OWASP ModSecurity Core Rule Set (CRS) patterns.

## Overview

The classification system analyzes HTTP request/response logs to identify and categorize web application attacks. It uses regular expression patterns derived from OWASP CRS, the industry-standard Web Application Firewall (WAF) ruleset, combined with custom patterns for attack types not fully covered by CRS.

## Classification Taxonomy

### Attack Families

| Family | Description | CAPEC | CWE | OWASP 2021 | Severity |
|--------|-------------|-------|-----|------------|----------|
| `sqli` | SQL Injection | CAPEC-66 | CWE-89 | A03 | Critical |
| `xss` | Cross-Site Scripting | CAPEC-86 | CWE-79 | A03 | Medium |
| `cmdi` | Command Injection | CAPEC-88 | CWE-78 | A03 | Critical |
| `path_traversal` | Path Traversal / LFI | CAPEC-126 | CWE-22 | A01 | High |
| `ssrf` | Server-Side Request Forgery | CAPEC-664 | CWE-918 | A10 | High |
| `info_disclosure` | Information Disclosure | CAPEC-118 | CWE-200 | A01 | Low |
| `auth_bypass` | Authentication Bypass | CAPEC-115 | CWE-287 | A07 | High |
| `file_upload` | Malicious File Upload | CAPEC-1 | CWE-434 | A04 | High |
| `deserialization` | Insecure Deserialization | CAPEC-586 | CWE-502 | A08 | Critical |
| `others` | Unclassified Requests | - | - | - | Info |

### CRS Rule Mapping

| CRS Rule Range | Attack Family | Description |
|----------------|---------------|-------------|
| 913xxx | `info_disclosure` | Scanner/bot detection |
| 930xxx | `path_traversal` | Local File Inclusion |
| 931xxx | `ssrf` | Remote File Inclusion / SSRF |
| 932xxx | `cmdi` | Remote Code Execution |
| 933xxx | `cmdi` | PHP Injection |
| 934xxx | `cmdi` | Node.js Injection |
| 941xxx | `xss` | Cross-Site Scripting |
| 942xxx | `sqli` | SQL Injection |
| 943xxx | `auth_bypass` | Session Fixation |
| 944xxx | `deserialization` | Java/Application Attacks |

## Methodology

### 1. Pattern Extraction

Patterns are extracted from OWASP CRS v4.x configuration files:

```
coreruleset/
├── rules/
│   ├── REQUEST-913-SCANNER-DETECTION.conf
│   ├── REQUEST-930-APPLICATION-ATTACK-LFI.conf
│   ├── REQUEST-931-APPLICATION-ATTACK-RFI.conf
│   ├── REQUEST-932-APPLICATION-ATTACK-RCE.conf
│   ├── REQUEST-941-APPLICATION-ATTACK-XSS.conf
│   ├── REQUEST-942-APPLICATION-ATTACK-SQLI.conf
│   └── REQUEST-944-APPLICATION-ATTACK-JAVA.conf
```

Each `SecRule` directive's regex pattern is simplified for log analysis (removing ModSecurity-specific operators like `@rx`, `@pmFromFile`, etc.).

### 2. Pattern Matching Process

For each HTTP log entry:

1. **Extract searchable text**: Combine URL path, query parameters, request body, and relevant headers
2. **Apply patterns**: Match against all CRS-derived patterns
3. **Aggregate matches**: Group matches by attack family
4. **Determine primary family**: Select based on:
   - Highest severity matches
   - Number of pattern matches
5. **Identify variants**: Map specific CRS rules to technique variants

### 3. Attack Label Structure

Each classified request receives an `attack_label` field:

```json
{
  "attack_label": {
    "family": "sqli",
    "matched_rules": ["942100", "942190", "942260"],
    "capec_id": "CAPEC-66",
    "cwe_id": "CWE-89"
  }
}
```

| Field | Description |
|-------|-------------|
| `family` | Attack category (sqli, xss, cmdi, etc.) |
| `matched_rules` | CRS rule IDs that matched |
| `capec_id` | MITRE CAPEC identifier |
| `cwe_id` | MITRE CWE identifier |

### 4. "Others" Classification

Requests that don't match any attack pattern are labeled as `others`:

```json
{
  "attack_label": {
    "family": "others",
    "matched_rules": [],
    "capec_id": null,
    "cwe_id": null
  }
}
```

This includes:
- Normal/benign HTTP requests
- Unknown attack patterns not in CRS
- Requests with insufficient data for classification

## Limitations

### HTTP Log-Only Classification

Some attack types cannot be reliably classified from HTTP logs alone:

| Attack Type | Limitation |
|-------------|------------|
| **IDOR** (Insecure Direct Object Reference) | Requires business logic context; a request to `/api/users/123` may or may not be unauthorized |
| **CSRF** (Cross-Site Request Forgery) | Requires analysis of token presence AND victim context; HTTP log alone cannot determine if request is forged |
| **Broken Access Control** | Requires authentication/authorization context |
| **Business Logic Flaws** | Requires application-specific knowledge |

### False Positives/Negatives

- **False Positives**: Legitimate requests containing SQL keywords, special characters in usernames, etc.
- **False Negatives**: Novel attack techniques not covered by CRS patterns, heavily obfuscated payloads

### Pattern Coverage

The implemented patterns are a subset of the full CRS ruleset, focusing on the most common and reliable patterns. Production WAF deployments should use the complete CRS.

## Implementation

### Files

| File | Purpose |
|------|---------|
| `attack_taxonomy.py` | Attack family definitions, CAPEC/CWE mappings |
| `crs_patterns.py` | CRS-derived regex patterns |
| `classify_attacks.py` | Main classifier script |

### Usage

```bash
# Classify a single HTTP log file
python3 classify_attacks.py input.jsonl -o output.jsonl

# Classify all logs in a session
python3 classify_attacks.py results/20260205_075407/http-logs/ -o results/20260205_075407/analysis/

# Output statistics only
python3 classify_attacks.py input.jsonl --stats-only
```

## References

### Primary Sources

1. **OWASP ModSecurity Core Rule Set (CRS)**
   - Repository: https://github.com/coreruleset/coreruleset
   - Version: v4.x
   - License: Apache 2.0

2. **MITRE CAPEC** (Common Attack Pattern Enumeration and Classification)
   - Website: https://capec.mitre.org/
   - Used for attack pattern identification

3. **MITRE CWE** (Common Weakness Enumeration)
   - Website: https://cwe.mitre.org/
   - Used for vulnerability classification

4. **OWASP Top 10 2021**
   - Website: https://owasp.org/Top10/
   - Used for risk categorization

### Academic References

5. **ModSec-Learn: Boosting ModSecurity with Machine Learning**
   - Authors: Zolotukhin et al.
   - Source: arXiv, 2024
   - Relevance: ML-enhanced CRS pattern matching

6. **SR-BH: A Dataset for Web Attack Detection**
   - Authors: Betarte et al.
   - Source: Computers & Security, 2022
   - Relevance: HTTP attack dataset methodology

7. **A Survey on SQL Injection Attack Detection and Prevention**
   - Authors: Sadeghian et al.
   - Source: Journal of Network and Computer Applications, 2020

## Citation

If using this classification methodology in academic work:

```bibtex
@misc{http-attack-classifier-2026,
  title={HTTP Attack Log Classification using OWASP CRS Patterns},
  author={LLM Cyber Attack Bias Research},
  year={2026},
  note={Based on OWASP ModSecurity Core Rule Set v4.x}
}
```

## Appendix: Sample Classifications

### SQL Injection

**Request:**
```
GET /rest/products/search?q='))UNION SELECT * FROM Users-- HTTP/1.1
```

**Classification:**
```json
{
  "family": "sqli",
  "matched_rules": ["942100", "942120", "942180"],
  "capec_id": "CAPEC-66",
  "cwe_id": "CWE-89"
}
```

### Path Traversal

**Request:**
```
GET /ftp/..%252f..%252f..%252fetc%252fpasswd HTTP/1.1
```

**Classification:**
```json
{
  "family": "path_traversal",
  "matched_rules": ["930100", "930120", "930160"],
  "capec_id": "CAPEC-126",
  "cwe_id": "CWE-22"
}
```

### XSS

**Request:**
```
GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1
```

**Classification:**
```json
{
  "family": "xss",
  "matched_rules": ["941100", "941110", "941180"],
  "capec_id": "CAPEC-86",
  "cwe_id": "CWE-79"
}
```

### Benign Request (Others)

**Request:**
```
GET /api/Products/1 HTTP/1.1
```

**Classification:**
```json
{
  "family": "others",
  "matched_rules": [],
  "capec_id": null,
  "cwe_id": null
}
```
