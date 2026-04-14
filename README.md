# 🛡️ DominoAD: Active Directory Attack Path Collector & Analyzer

[![Status](https://img.shields.io/badge/status-active-success.svg)](https://github.com/cyeezy08/DominoAD)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://github.com/cyeezy08/DominoAD)
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](https://github.com/cyeezy08/DominoAD)
[![Active Directory](https://img.shields.io/badge/Security-Active%20Directory-red.svg)](https://github.com/cyeezy08/DominoAD)

**DominoAD** is a lightweight, transparent, and fully offline tool designed to map Active Directory environments, uncover hidden privilege escalation paths, and visualize attack surfaces. Built from the ground up to provide a clear, "no black box" understanding of AD abuse paths.

---

## 🚀 Key Features

### 🔍 Comprehensive Collection
- **LDAP Enumeration**: Deep dive into Users, Groups, Computers, OUs, and GPOs.
- **Relationship Mapping**: Automatically identifies group memberships and nested hierarchies.
- **SMB/RPC Insights**: Discovers active sessions and local administrator relationships.
- **Vulnerability Flags**: Instantly identifies Kerberoastable accounts, AS-REP roastable accounts, and AdminCount users.

### 🧠 Intelligent Graph Engine
- **Directed Graph Model**: Models your AD as a complex network of nodes and edges.
- **Node Types**: User, Group, Computer, GPO, OU.
- **Edge Types**: `MemberOf`, `AdminTo`, `HasSession`.

### ⚡ Advanced Analysis
- **BFS-Based Discovery**: Uses Breadth-First Search to find the shortest, most efficient attack paths.
- **Pre-built Security Queries**:
  - 🎯 **Paths to Domain Admins**: Identify every route to the "keys to the kingdom."
  - 🌊 **Blast Radius**: Measure the potential impact of a compromised account.
  - 🛑 **Chokepoints**: Find the critical nodes that, if secured, break multiple attack paths.
- **Severity-Based Reporting**: Clear, actionable reports categorized by risk level.

---

## 🛠️ Installation

Ensure you have Python 3.9+ installed, then install the dependencies:

```bash
pip install ldap3 impacket
```

---

## 📖 Usage

### Full Execution (Collect + Analyze)
```bash
python cli.py \
  --host 10.10.10.100 \
  --domain corp.local \
  --username "corp\administrator" \
  --password Password123
```

### Pass-the-Hash Support
```bash
python cli.py \
  --host 10.10.10.100 \
  --domain corp.local \
  --username administrator \
  --nt-hash <YOUR_NT_HASH>
```

### Analysis Only (Offline Mode)
```bash
python cli.py --analyze-only --graph output/graph.json
```

### Targeted Security Queries
```bash
# Shortest paths to Domain Admins
python cli.py --analyze-only --query da-paths

# Kerberoastable users with a path to DA
python cli.py --analyze-only --query kerb

# Chokepoint nodes identification
python cli.py --analyze-only --query chokepoints

# Blast radius analysis for a specific user
python cli.py --analyze-only --query "blast:jsmith"
```

---

## 📊 Sample Output

```text
============================================================
  DominoAD — ATTACK PATH REPORT
============================================================

SUMMARY
  [CRITICAL] 2 finding(s)
  [HIGH] 3 finding(s)
  [MEDIUM] 1 finding(s)

FINDINGS
------------------------------------------------------------

[CRITICAL] 2 direct path(s) to Domain Admins
  Users/groups with 1-2 hop paths to Domain Admins.
  Affected:
    • svc_backup
    • helpdesk_admin
  Example path:
    svc_backup[MemberOf] -> Backup Operators[MemberOf] -> Domain Admins
```

---

## 🧪 Testing Grounds

DominoAD has been rigorously tested in the following environments:
- ✅ **TryHackMe**: Attacktive Directory, Throwback
- ✅ **GOAD** (Game of Active Directory) lab
- ⚠️ *Note: Currently optimized for lab environments; real-world production testing is ongoing.*

---

## ⚖️ Disclaimer

This tool is for **authorized security testing and research only**. Only run against environments you own or have explicit written permission to test. The author is not responsible for any misuse or damage caused by this tool.

---

## 🤝 Acknowledgments

Special thanks to [@Cannatag](https://github.com/cannatag) for the inspiration and foundational concepts that made this project possible.

---
<p align="center">Made with ❤️ for the Security Community</p>
