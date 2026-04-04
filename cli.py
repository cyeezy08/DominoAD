#!/usr/bin/env python3
"""
cli.py
------
AD Analyzer — main entry point.

Usage:
    python cli.py --host 10.10.10.100 --domain corp.local \
                  --username corp\\\\administrator --password Password123

    python cli.py --host 10.10.10.100 --domain corp.local \
                  --username administrator --nt-hash <HASH>

    # Analyze only (skip collection, use saved graph)
    python cli.py --analyze-only --graph output/graph.json
"""

import argparse
import logging
import sys
import os
import json
from pathlib import Path

# Make local imports work regardless of cwd
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "collector"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "graph"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "analyzer"))

from config import Config
from ldap_collector import LDAPCollector, LDAPConfig
from smb_collector import SMBCollector, SMBConfig
from graph_builder import GraphBuilder
from graph_store import GraphStore
from bfs_engine import BFSEngine
from queries import QueryEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

BANNER = r"""
  █████╗ ██████╗      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
 ██╔══██╗██╔══██╗    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
 ███████║██║  ██║    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
 ██╔══██║██║  ██║    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
 ██║  ██║██████╔╝    ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
 ╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
  Active Directory Attack Path Analyzer
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="AD Analyzer — collect and analyze Active Directory attack paths"
    )
    p.add_argument("--host",       help="DC IP or hostname")
    p.add_argument("--domain",     help="Domain (e.g. corp.local)")
    p.add_argument("--username",   help="Username (e.g. corp\\\\administrator)")
    p.add_argument("--password",   default="", help="Password")
    p.add_argument("--nt-hash",    default="", help="NT hash for pass-the-hash")
    p.add_argument("--lm-hash",    default="", help="LM hash (usually empty)")
    p.add_argument("--no-sessions",    action="store_true", help="Skip SMB session enumeration")
    p.add_argument("--no-local-admins",action="store_true", help="Skip local admin enumeration")
    p.add_argument("--output-dir", default="output", help="Output directory")
    p.add_argument("--analyze-only", action="store_true", help="Skip collection, analyze saved graph")
    p.add_argument("--graph",      default="output/graph.json", help="Path to saved graph (for --analyze-only)")
    p.add_argument("--query",      help="Run a single query: da-paths | kerb | asrep | chokepoints | blast:<label>")
    p.add_argument("--verbose",    action="store_true")
    return p.parse_args()


def build_config(args) -> Config:
    cfg = Config()
    cfg.dc_host = args.host or ""
    cfg.domain  = args.domain or ""
    cfg.username = args.username or ""
    cfg.password = args.password or ""
    cfg.nt_hash  = args.nt_hash or ""
    cfg.lm_hash  = args.lm_hash or ""
    cfg.collect_sessions     = not args.no_sessions
    cfg.collect_local_admins = not args.no_local_admins
    cfg.output_dir  = args.output_dir
    cfg.graph_file  = str(Path(args.output_dir) / "graph.json")
    cfg.report_file = str(Path(args.output_dir) / "report.txt")
    return cfg


def run_collection(cfg: Config):
    """Phase 1 + 2: collect AD data and build graph."""

    # --- LDAP ---
    logger.info("[*] Starting LDAP collection...")
    ldap_cfg = LDAPConfig(
        host=cfg.dc_host,
        domain=cfg.domain,
        username=cfg.username,
        password=cfg.password,
        port=cfg.ldap_port,
        use_ssl=cfg.use_ssl,
        auth_method=cfg.auth_method,
    )
    collector = LDAPCollector(ldap_cfg)
    if not collector.connect():
        logger.error("[-] LDAP connection failed. Exiting.")
        sys.exit(1)

    ad_data = collector.collect_all()
    collector.disconnect()

    # --- SMB ---
    smb_sessions = []
    smb_admins   = []

    if cfg.collect_sessions or cfg.collect_local_admins:
        logger.info("[*] Starting SMB collection...")
        smb_cfg = SMBConfig(
            domain=cfg.domain,
            username=cfg.username.split("\\")[-1],   # strip domain prefix
            password=cfg.password,
            lm_hash=cfg.lm_hash,
            nt_hash=cfg.nt_hash,
            timeout=cfg.smb_timeout,
        )
        smb = SMBCollector(smb_cfg)

        if cfg.collect_sessions:
            smb_sessions = smb.get_sessions(ad_data.computers)
        if cfg.collect_local_admins:
            smb_admins = smb.get_local_admins(ad_data.computers)

    # --- Graph ---
    logger.info("[*] Building graph...")
    builder = GraphBuilder()
    graph = builder.build(ad_data, smb_sessions or None, smb_admins or None)

    # Save raw collection data
    Path(cfg.output_dir).mkdir(parents=True, exist_ok=True)
    raw_path = str(Path(cfg.output_dir) / "raw_collection.json")
    with open(raw_path, "w") as f:
        json.dump({
            "users":     ad_data.users,
            "groups":    ad_data.groups,
            "computers": ad_data.computers,
        }, f, indent=2, default=str)
    logger.info(f"[+] Raw data saved to {raw_path}")

    GraphStore.save(graph, cfg.graph_file)
    return graph


def run_analysis(graph, cfg: Config, single_query: str = None):
    """Phase 3: analyze graph, generate report."""
    engine = QueryEngine(graph)

    if single_query:
        _run_single_query(engine, graph, single_query)
        return

    logger.info("[*] Running full analysis...")
    findings = engine.run_all()
    report = engine.format_report(findings)

    print("\n" + report)

    with open(cfg.report_file, "w") as f:
        f.write(report)
    logger.info(f"[+] Report saved to {cfg.report_file}")

    # Summary stats
    summary = GraphStore.export_summary(graph)
    summary_path = str(Path(cfg.output_dir) / "summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    logger.info(f"[+] Summary saved to {summary_path}")


def _run_single_query(engine: QueryEngine, graph, query: str):
    bfs = BFSEngine(graph)

    if query == "da-paths":
        paths = bfs.find_da_paths()
        print(f"\n[+] Paths to Domain Admins: {len(paths)}")
        for p in paths[:20]:
            print(f"  [{p.length} hops] {' -> '.join(p.path_labels)}")

    elif query == "kerb":
        paths = bfs.kerberoastable_to_da()
        print(f"\n[+] Kerberoastable → DA paths: {len(paths)}")
        for p in paths:
            print(f"  {p.src_label} → DA ({p.length} hops): {' -> '.join(p.path_labels)}")

    elif query == "asrep":
        paths = bfs.asreproastable_to_da()
        print(f"\n[+] ASREPRoastable → DA paths: {len(paths)}")
        for p in paths:
            print(f"  {p.src_label} → DA ({p.length} hops): {' -> '.join(p.path_labels)}")

    elif query == "chokepoints":
        ranked = bfs.find_chokepoints()
        print("\n[+] Top chokepoints on paths to Domain Admins:")
        for nid, count in ranked[:10]:
            node = graph.nodes.get(nid)
            if node:
                print(f"  {node.label} ({node.type}) — {count} path(s)")

    elif query.startswith("blast:"):
        label = query.split(":", 1)[1]
        src_id = None
        for nid, n in graph.nodes.items():
            if n.label.lower() == label.lower():
                src_id = nid
                break
        if not src_id:
            print(f"[-] Node not found: {label}")
            return
        reachable = bfs.blast_radius(src_id)
        print(f"\n[+] Blast radius from '{label}': {len(reachable)} reachable nodes")
        for nid in reachable[:20]:
            n = graph.nodes.get(nid)
            if n:
                print(f"  {n.label} ({n.type})")

    else:
        print(f"[-] Unknown query: {query}")
        print("    Valid: da-paths | kerb | asrep | chokepoints | blast:<label>")


def main():
    print(BANNER)
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    cfg = build_config(args)

    if args.analyze_only:
        logger.info(f"[*] Loading graph from {args.graph}")
        graph = GraphStore.load(args.graph)
    else:
        if not all([cfg.dc_host, cfg.domain, cfg.username]):
            print("[-] --host, --domain, and --username are required for collection.")
            print("    Use --analyze-only to skip collection and analyze a saved graph.")
            sys.exit(1)
        graph = run_collection(cfg)

    run_analysis(graph, cfg, single_query=args.query)


if __name__ == "__main__":
    main()
