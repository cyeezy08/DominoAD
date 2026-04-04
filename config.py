"""
config.py
---------
Central configuration for an AD Analyzer run.
Edit this file or pass values via CLI args.
"""

from dataclasses import dataclass, field


@dataclass
class Config:
    # Target
    dc_host: str = ""           # IP or hostname of a DC
    domain: str = ""            # e.g. corp.local

    # Credentials
    username: str = ""          # e.g. corp\\jsmith  or  jsmith@corp.local
    password: str = ""
    lm_hash: str = ""           # pass-the-hash (leave blank if using password)
    nt_hash: str = ""

    # LDAP options
    ldap_port: int = 389
    use_ssl: bool = False
    auth_method: str = "NTLM"   # NTLM | SIMPLE

    # Collection flags
    collect_sessions: bool = True
    collect_local_admins: bool = True
    smb_timeout: int = 5        # seconds per host

    # Output
    output_dir: str = "output"
    graph_file: str = "output/graph.json"
    report_file: str = "output/report.txt"

    # Analysis
    max_path_depth: int = 6
