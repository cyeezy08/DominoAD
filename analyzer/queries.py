"""
queries.py
----------
High-level query interface.
Wraps BFSEngine + graph data into structured findings.

These are the "so what" outputs — what you'd put in a report
or display in a dashboard.
"""

import logging
from dataclasses import dataclass, field
from bfs_engine import BFSEngine, AttackPath

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    detail: str
    affected: list[str] = field(default_factory=list)
    paths: list[AttackPath] = field(default_factory=list)


class QueryEngine:
    def __init__(self, graph):
        self.graph = graph
        self.bfs = BFSEngine(graph)

    def run_all(self) -> list[Finding]:
        """Run all queries. Returns sorted list of Findings."""
        findings = []

        findings += self.q_paths_to_da()
        findings += self.q_kerberoastable()
        findings += self.q_asreproastable()
        findings += self.q_password_never_expires()
        findings += self.q_disabled_privileged()
        findings += self.q_chokepoints()
        findings += self.q_sessions_on_dcs()

        findings.sort(key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(f.severity))
        return findings

    # ------------------------------------------------------------------ #
    #  Query methods                                                       #
    # ------------------------------------------------------------------ #

    def q_paths_to_da(self) -> list[Finding]:
        paths = self.bfs.find_da_paths()
        if not paths:
            return [Finding(
                severity="INFO",
                title="No paths to Domain Admins found",
                detail="No attack paths to Domain Admins were identified from current data."
            )]

        # Bucket by path length
        direct = [p for p in paths if p.length <= 2]
        short  = [p for p in paths if 2 < p.length <= 4]
        long   = [p for p in paths if p.length > 4]

        findings = []
        if direct:
            findings.append(Finding(
                severity="CRITICAL",
                title=f"{len(direct)} direct path(s) to Domain Admins",
                detail="Users/groups with 1-2 hop paths to Domain Admins.",
                affected=[p.src_label for p in direct],
                paths=direct
            ))
        if short:
            findings.append(Finding(
                severity="HIGH",
                title=f"{len(short)} short path(s) to Domain Admins (3-4 hops)",
                detail="Accounts with short attack paths to DA.",
                affected=[p.src_label for p in short],
                paths=short
            ))
        if long:
            findings.append(Finding(
                severity="MEDIUM",
                title=f"{len(long)} longer path(s) to Domain Admins (5+ hops)",
                detail="Accounts with longer but valid attack paths to DA.",
                affected=[p.src_label for p in long],
                paths=long[:10]  # cap for readability
            ))
        return findings

    def q_kerberoastable(self) -> list[Finding]:
        paths = self.bfs.kerberoastable_to_da()
        kerberoastable_all = [
            n.label for n in self.graph.nodes.values()
            if n.type == "user" and n.properties.get("kerberoastable")
        ]

        findings = []
        if paths:
            findings.append(Finding(
                severity="CRITICAL",
                title=f"{len(paths)} kerberoastable user(s) with path to Domain Admins",
                detail=(
                    "These accounts have SPNs (Kerberoastable) AND a path to DA. "
                    "Offline cracking of their TGS tickets could lead to full domain compromise."
                ),
                affected=[p.src_label for p in paths],
                paths=paths
            ))

        if kerberoastable_all:
            findings.append(Finding(
                severity="HIGH",
                title=f"{len(kerberoastable_all)} kerberoastable user(s) in total",
                detail="All users with SPNs are eligible for Kerberoasting.",
                affected=kerberoastable_all
            ))

        return findings

    def q_asreproastable(self) -> list[Finding]:
        paths = self.bfs.asreproastable_to_da()
        asrep_all = [
            n.label for n in self.graph.nodes.values()
            if n.type == "user" and n.properties.get("asreproastable")
        ]

        findings = []
        if paths:
            findings.append(Finding(
                severity="CRITICAL",
                title=f"{len(paths)} ASREPRoastable user(s) with path to Domain Admins",
                detail=(
                    "These accounts have 'Do not require Kerberos preauthentication' set "
                    "AND have a path to DA. No credentials needed to request their AS-REP."
                ),
                affected=[p.src_label for p in paths],
                paths=paths
            ))
        if asrep_all:
            findings.append(Finding(
                severity="HIGH",
                title=f"{len(asrep_all)} ASREPRoastable user(s) in total",
                detail="Preauthentication not required — AS-REP hashes can be requested without credentials.",
                affected=asrep_all
            ))

        return findings

    def q_password_never_expires(self) -> list[Finding]:
        affected = [
            n.label for n in self.graph.nodes.values()
            if n.type == "user"
            and n.properties.get("password_never_expires")
            and n.properties.get("enabled", True)
        ]
        if not affected:
            return []
        return [Finding(
            severity="MEDIUM",
            title=f"{len(affected)} enabled user(s) with password set to never expire",
            detail="Stale passwords increase the window for credential-based attacks.",
            affected=affected
        )]

    def q_disabled_privileged(self) -> list[Finding]:
        """Disabled accounts that are still members of privileged groups."""
        high_value_group_ids = {
            nid for nid, n in self.graph.nodes.items()
            if n.type == "group" and n.properties.get("is_high_value")
        }

        member_of = {}
        for edge in self.graph.edges:
            if edge.relation == "MemberOf":
                member_of.setdefault(edge.src, set()).add(edge.dst)

        affected = []
        for nid, n in self.graph.nodes.items():
            if n.type == "user" and not n.properties.get("enabled", True):
                memberships = member_of.get(nid, set())
                if memberships & high_value_group_ids:
                    affected.append(n.label)

        if not affected:
            return []
        return [Finding(
            severity="LOW",
            title=f"{len(affected)} disabled account(s) still in privileged groups",
            detail="Disabled accounts in privileged groups are a hygiene issue and should be cleaned up.",
            affected=affected
        )]

    def q_chokepoints(self) -> list[Finding]:
        ranked = self.bfs.find_chokepoints()
        if not ranked:
            return []

        top = ranked[:5]
        affected = []
        for nid, count in top:
            node = self.graph.nodes.get(nid)
            if node:
                affected.append(f"{node.label} ({node.type}) — on {count} attack path(s)")

        return [Finding(
            severity="INFO",
            title=f"Top {len(top)} chokepoint node(s) on paths to Domain Admins",
            detail=(
                "These nodes appear on the most attack paths. "
                "Defending them (monitoring, tiering, credential isolation) "
                "has the highest leverage."
            ),
            affected=affected
        )]

    def q_sessions_on_dcs(self) -> list[Finding]:
        """Non-admin users with sessions on Domain Controllers."""
        dc_ids = {
            nid for nid, n in self.graph.nodes.items()
            if n.type == "computer" and (
                "domain controller" in n.label.lower() or
                "dc" in n.label.lower()
            )
        }

        da_group_id = None
        for nid, n in self.graph.nodes.items():
            if n.type == "group" and n.label.lower() == "domain admins":
                da_group_id = nid
                break

        # Users with HasSession on a DC
        risky_sessions = []
        for edge in self.graph.edges:
            if edge.relation == "HasSession" and edge.dst in dc_ids:
                node = self.graph.nodes.get(edge.src)
                if node:
                    risky_sessions.append(node.label)

        if not risky_sessions:
            return []

        return [Finding(
            severity="HIGH",
            title=f"{len(risky_sessions)} user session(s) detected on Domain Controllers",
            detail=(
                "Interactive or network sessions on DCs expose credentials to memory scraping. "
                "Only privileged admin accounts should have sessions on DCs."
            ),
            affected=risky_sessions
        )]

    # ------------------------------------------------------------------ #
    #  Report formatter                                                    #
    # ------------------------------------------------------------------ #

    def format_report(self, findings: list[Finding]) -> str:
        """Plain-text report output."""
        lines = []
        lines.append("=" * 60)
        lines.append("  AD ANALYZER — ATTACK PATH REPORT")
        lines.append("=" * 60)

        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        lines.append("\nSUMMARY")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            if count:
                lines.append(f"  [{sev}] {count} finding(s)")

        lines.append("\nFINDINGS\n" + "-" * 60)

        for f in findings:
            lines.append(f"\n[{f.severity}] {f.title}")
            lines.append(f"  {f.detail}")
            if f.affected:
                lines.append(f"  Affected ({min(len(f.affected), 10)} shown):")
                for item in f.affected[:10]:
                    lines.append(f"    • {item}")

            if f.paths:
                lines.append(f"  Example path:")
                p = f.paths[0]
                path_str = " → ".join(
                    f"{lbl}[{rel}]" if i < len(p.path_edges) else lbl
                    for i, (lbl, rel) in enumerate(
                        zip(p.path_labels, p.path_edges + [""])
                    )
                )
                lines.append(f"    {path_str}")

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)
