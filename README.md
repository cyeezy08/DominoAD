# DominoAD

<p align="center">
  <b>Active Directory attack path collector and analyzer</b><br>
  Built from scratch to understand how AD abuse paths actually work.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-active-success.svg">
  <img src="https://img.shields.io/badge/python-3.9+-blue.svg">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey.svg">
</p>

---

## Overview

DominoAD collects data from an Active Directory environment, models it as a graph, and analyzes it to uncover privilege escalation paths.

The goal is simple:
- No black box logic
- Fully traceable attack paths
- Clean, readable output

---

## Features

### Collection
- LDAP enumeration:
  - Users, groups, computers
  - OUs and GPOs
  - Group memberships
- SMB/RPC enumeration:
  - Active sessions
  - Local admin relationships
- Flags:
  - Kerberoastable accounts
  - AS-REP roastable accounts
  - AdminCount users

---

### Graph Engine
- Directed graph model
- Node types:
  - User
  - Group
  - Computer
  - GPO
  - OU
- Edge types:
  - MemberOf
  - AdminTo
  - HasSession

---

### Analysis Engine
- BFS-based attack path discovery
- Built-in queries:
  - Paths to Domain Admins
  - Blast radius
  - Chokepoints
- Severity-based reporting

---

## Installation

```bash
pip install ldap3 impacket
```



## Usage

### Full run (collect + analyze)
```bash
python cli.py \
  --host 10.10.10.100 \
  --domain corp.local \
  --username "corp\administrator" \
  --password Password123
```

### Pass-the-hash
```bash
python cli.py \
  --host 10.10.10.100 \
  --domain corp.local \
  --username administrator \
  --nt-hash aad3b435b51404eeaad3b435b51404ee
```

### Analyze only (no collection)
```bash
python cli.py --analyze-only --graph output/graph.json
```

### Single queries
```bash
# Shortest paths to Domain Admins
python cli.py --analyze-only --query da-paths

# Kerberoastable users with DA path
python cli.py --analyze-only --query kerb

# ASREPRoastable users with DA path
python cli.py --analyze-only --query asrep

# Chokepoint nodes
python cli.py --analyze-only --query chokepoints

# Blast radius from an account
python cli.py --analyze-only --query "blast:jsmith"
```

---

## Output files

```
output/
├── graph.json           # full serialized graph
├── raw_collection.json  # raw LDAP data
├── report.txt           # findings report
└── summary.json         # quick stats
```

---

## Project structure

```
ad-analyzer/
├── collector/
│   ├── ldap_collector.py   # LDAP enumeration
│   └── smb_collector.py    # SMB session + local admin enum
├── graph/
│   ├── graph_builder.py    # build nodes + edges
│   └── graph_store.py      # JSON serialization
├── analyzer/
│   ├── bfs_engine.py       # BFS attack path engine
│   └── queries.py          # findings + report
├── cli.py                  # entry point
├── config.py               # configuration
└── README.md
```

---

## Sample findings output

```
============================================================
  AD ANALYZER — ATTACK PATH REPORT
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

[CRITICAL] 1 kerberoastable user(s) with path to Domain Admins
  These accounts have SPNs (Kerberoastable) AND a path to DA.
  Affected:
    • svc_mssql
  Example path:
    svc_mssql[MemberOf] -> DBAdmins[AdminTo] -> DC01
```

---

## Testing

Tested against:
- **TryHackMe**: Attacktive Directory, Throwback
- **GOAD** (Game of Active Directory) lab

---

## Disclaimer

This tool is for authorized security testing and research only.  
Only run against environments you own or have explicit written permission to test.
