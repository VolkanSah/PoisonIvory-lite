# PoisonIvory - Nemesis//NF

###### Version 1.4.1 - Codename: "Nemesis Reborn" - Security Patterns v.2026

> Dual License: ESOL v1.0 + GPLv3

### Advanced Security & Threat Monitoring (DIY)

> [!WARNING]
> Professional Use Only - Handle With Extreme Care!
> This tool is designed for experienced security professionals and red/blue teams. It provides a battle-tested (mini)framework for infrastructure hardening, threat detection, and offensive security research.
> PoisonIvory is not for script kiddies. It intentionally requires deep technical knowledge to operate effectively. Expect to troubleshoot missing dependencies, analyze raw outputs, and interpret security events without hand-holding.

---

## What is PoisonIvory?

PoisonIvory is a security operations micro-framework combining deep infrastructure auditing with continuous threat monitoring. It is built to emulate advanced adversarial techniques for defensive research and can be extended freely to fit your operational needs.

- **Infrastructure Auditing** - Comprehensive scanning of domains, onion services, and network assets.
- **AI-Era Threat Detection** - Real-time detection of LLM prompt injection, AI agent hijacking, and quantum harvesting attacks.
- **Vulnerability Assessment** - Integration with industry-standard tools (Nmap, Nuclei, SSLScan, etc.).
- **Tor Circuit Management** - Active monitoring and defense against malicious Tor relays.
- **Automated Response** - Threshold-based emergency scanning and detailed forensic reporting.
- **Blue Team Integration** - Framework for continuous monitoring and threat intelligence collection within your own security perimeter.

Built for:
- Red/Blue team operations in authorized environments only.
- Critical infrastructure hardening and compliance checks.
- Security research and adversary simulation in the AI/Quantum era.
- Training of elite security professionals.

---

## Key Features

### Core Capabilities
- JSON-based configuration system for enterprise deployment.
- Modular architecture supporting custom security workflows.
- **Nuclear Fusion Mode** for stress testing infrastructure limits under controlled conditions.
- **SecurityPatterns2026 Class** with 150+ patterns covering modern threat categories.
- **Risk Scoring System** - Automatic CRITICAL/HIGH/MEDIUM/LOW classification.
- Original architecture preserved while enhancing security and performance.

### Security Integrations

| Tool | Function |
|---|---|
| Nmap | Aggressive port scanning and service enumeration. |
| Nuclei | Fast, template-based vulnerability detection. |
| SSLScan | TLS/SSL configuration audit and protocol weakness detection. |
| Tor Control | Circuit management and automated renewal for testing isolation. |
| Scapy/Raw | Low-level packet monitoring and payload analysis. |
| OpenVAS | External comprehensive vulnerability assessment via API (if configured). |

### Advanced Operations
- 2026 threat patterns covering LLM injection, AI agent attacks, quantum harvesting, and container escape.
- Automatic emergency scanning on high-confidence threat detection.
- Continuous monitoring with periodic health checks and DNS rebinding protection.
- Comprehensive JSON reporting for forensic analysis.
- Anti-loop mechanisms for stable Tor circuit renewal.

---

## Requirements

### Mandatory
- Python 3.9+ (3.11+ recommended)
- Linux environment (Kernel 5.4+ recommended)
- Root privileges required for Nuclear Mode kernel-level operations.

### Security Tools (Partial List)
```bash
# Minimum core dependencies
nmap nikto sslscan testssl.sh

# Minimum Python modules
requests stem scapy ipaddress
```

> **Expert Notice**
> No automatic dependency checks are included - this is intentional. You are expected to:
>
> 1. Understand your environment and legal scope.
> 2. Install necessary tools, including advanced scanners like Nuclei, Wapiti, and OpenVAS.
> 3. Resolve errors through analysis.
> 4. Modify configurations for your operational needs.

---

## Configuration

### Minimum Example `cms_security_config.json`

```json
{
  "domain": "yourdomain.com",
  "onion_address": "youronionaddress.onion",
  "tor_control_port": 9051,
  "tor_password": "your_tor_password",
  "output_dir": "security_reports",
  "alert_threshold": 5,
  "malicious_relays": ["ABCD1234EFGH5678", "IJKL91011MNOP1213"],
  "malicious_patterns": ["(?i)(malware|exploit|ransomware)", "(?i)(wp-admin|phpmyadmin)"],
  "nuclear_mode": false
}
```

> **Note: SecurityPatterns2026**
> The 2026 patterns are hardcoded in the `SecurityPatterns2026` class and cover AI/LLM threats, quantum attacks, container escape vectors, and modern supply chain attacks. No additional configuration required.

---

## Usage

### Command Structure

```bash
PoisonIvory.py [COMMAND] <config_file>
```

### Operations

| Command | Function |
|---|---|
| `scan` | Run full security audit (port scanning and vulnerability assessment). |
| `monitor` | Start continuous monitoring of network traffic and system health. |
| `create-config` | Generate default configuration file. |

### Nuclear Mode

Enable `nuclear_mode` in your config for high-intensity operations. When active, PoisonIvory will:

- Increase network buffer sizes (requires root).
- Use aggressive scanning parameters (`-T5 --min-rate 5000`).
- Allocate additional system resources.
- Reduce monitoring intervals to 60 seconds.

Startup warning:
```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! NUCLEAR MODE ACTIVATED - EXPECT SYSTEM INSTABILITY !!
!!    Target servers may experience disruption          !!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### Examples

```bash
# Run security audit
python3 PoisonIvory.py scan config.json

# Start continuous monitoring
python3 PoisonIvory.py monitor config.json
```

---

## Design Philosophy

PoisonIvory is built on three principles:

**Expert-Centric** - No GUIs, no hand-holding. Raw terminal output and JSON reports only. If something breaks, you figure out why.

**Original Architecture Preserved** - Nuclear Fusion Edition maintains the original code structure. Security fixes are integrated without over-engineering the base. Existing users have a clean upgrade path.

**Offense-Informed Defense** - Adversary-emulating techniques for robust defense development. You cannot defend what you cannot attack.

---

## Legal Notice

- This tool must only be used on systems you own or for which you have explicit written authorization (Scope of Work).
- This software is provided as-is without any warranty.
- You are solely responsible for complying with all applicable laws and ethical guidelines regarding security testing.
- Unauthorized scanning, active exploitation, or traffic interception on systems you do not own is illegal and carries severe legal penalties in most jurisdictions.

---

## Changelog

### v1.4.1
[FIX]

**Bugs fixed:**
- `log_suspicious_activity` - `source_ip` sanitized against log injection via newline stripping.
- `vulnerability_assessment` - `target` sanitized with `re.sub` before file path construction (path injection).
- `_generate_executive_summary` - `suspicious_activity` now read under `self.lock` (race condition).
- `renew_tor_circuit` + `manage_tor_circuits` - both migrated to `with Controller.from_port(...) as controller` (resource leak on exception).

**Patterns fixed:**
- `apikey_openai` - updated to match current `sk-proj-*` / `sk-svcacct-*` format (old `sk-[48]` pattern matched nothing since mid-2024).
- `pqc_weak_ecdsa` renamed to `pqc_legacy_ecdsa` - P-256 is classically sound, quantum-vulnerable only; misleading name caused false escalations.
- `social_phishing`, `social_captcha`, `social_click_continue` - removed. Patterns were too broad and caused constant false-positive emergency scans on legitimate traffic.

All comments translated from German to English. No logic changes.

---

### v1.3.1 to v1.4.0

| Feature | v1.3.1 (2025) | v1.4.0 (2026) |
|---|---|---|
| Security Patterns | Basic SQLi/XSS/CMDi | 150+ AI/Quantum/Container patterns |
| Threat Detection | Traditional web attacks | + LLM injection, AI agent hijacking |
| Risk Assessment | Binary (malicious/clean) | 4-level scoring (CRITICAL to LOW) |
| Cryptography Focus | TLS/SSL weaknesses | + Post-quantum harvesting detection |
| Container Security | Limited | Escape vectors, K8s API protection |
| Command Safety | Some shell=True usage | All shell=False, proper sanitization |
| DNS Protection | Basic | Full rebinding protection |

### New Threat Categories in v1.4.0
1. **AI/LLM Security** - Prompt injection, agent manipulation, shadow AI detection.
2. **Quantum Cryptography** - Harvesting attacks, PQC migration gap detection.
3. **Container & Cloud Native** - Escape vectors, Kubernetes API security.
4. **Deepfake & Identity** - Synthetic fraud and AI impersonation detection.
5. **Supply Chain 2026** - AI-generated malicious packages, dependency confusion.

---

## Development & Credits

**Core Development:**
Volkan Kücükbudak ([@volkansah](https://github.com/volkansah)) - Lead Architect

**AI-Assisted:**
- Claude Sonnet 4.6 to write me an clean english Readme.md on 20.04.2026 after being lazy fixing bugs. (It works local) 😄 . Trust me my english is not so well any more, AI is better but not in coding logic! 
> This is not an VibeCode App this is RAW and dirty code (modular) you must read the code! 

This project is a human-AI collaboration where human expertise defined the operational requirements, security boundaries, and final decisions. The AI used for docs or comments

---

## Support the Project

1. Star the repo on [GitHub](https://github.com/VolkanSah/PoisonIvory).
2. Contribute via pull requests (experts only, no tutorial-quality PRs).
3. Sponsor ongoing development.
4. Use it ethically and share knowledge responsibly.

```
Copyright © 2008-2026 Volkan Kücükbudak
Dual Licensed: ESOL v2.0 (Ethical) + GPLv3

PoisonIvory Nuclear Fusion Edition - Version 1.4.1
Codename: "Nemesis Reborn"
Patterns Version: v.2026
```
