"""
graph_builder.py
----------------
Converts raw ADData into a graph of nodes and edges.

Node types:  User | Group | Computer | GPO | OU
Edge types:  MemberOf | AdminTo | HasSession | Contains | GPOAppliesTo

The graph is stored as two dicts:
  nodes: { node_id: NodeData }
  edges: [ EdgeData ]

This feeds directly into bfs_engine.py for attack path analysis.
"""

import logging
import hashlib
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Data structures                                                     #
# ------------------------------------------------------------------ #

@dataclass
class NodeData:
    id: str                    # unique stable ID (DN hash)
    label: str                 # display name (sAMAccountName or DN)
    type: str                  # user | group | computer | gpo | ou
    dn: str                    # full distinguished name
    properties: dict = field(default_factory=dict)

    def __hash__(self):
        return hash(self.id)


@dataclass
class EdgeData:
    src: str                   # source node ID
    dst: str                   # destination node ID
    relation: str              # MemberOf | AdminTo | HasSession | Contains
    properties: dict = field(default_factory=dict)


class ADGraph:
    """
    Lightweight graph container.
    nodes: dict[id -> NodeData]
    edges: list[EdgeData]
    """

    def __init__(self):
        self.nodes: dict[str, NodeData] = {}
        self.edges: list[EdgeData] = []
        self._dn_index: dict[str, str] = {}    # dn.lower() -> node_id

    def add_node(self, node: NodeData):
        self.nodes[node.id] = node
        self._dn_index[node.dn.lower()] = node.id

    def add_edge(self, edge: EdgeData):
        self.edges.append(edge)

    def get_id_by_dn(self, dn: str) -> Optional[str]:
        return self._dn_index.get(dn.lower())

    def stats(self) -> dict:
        from collections import Counter
        node_types = Counter(n.type for n in self.nodes.values())
        edge_types = Counter(e.relation for e in self.edges)
        return {"nodes": dict(node_types), "edges": dict(edge_types)}


# ------------------------------------------------------------------ #
#  Builder                                                             #
# ------------------------------------------------------------------ #

class GraphBuilder:
    def __init__(self):
        self.graph = ADGraph()

    def build(self, ad_data, smb_sessions=None, smb_admins=None) -> ADGraph:
        """
        Full build pipeline.
          1. Register all nodes
          2. Add MemberOf edges from LDAP memberships
          3. Add HasSession edges from SMB session data
          4. Add AdminTo edges from SMB local admin data
        """
        self._add_user_nodes(ad_data.users)
        self._add_group_nodes(ad_data.groups)
        self._add_computer_nodes(ad_data.computers)
        self._add_ou_nodes(ad_data.ous)
        self._add_gpo_nodes(ad_data.gpos)

        self._add_membership_edges(ad_data.memberships)

        if smb_sessions:
            self._add_session_edges(smb_sessions, ad_data.users)

        if smb_admins:
            self._add_admin_edges(smb_admins, ad_data.computers)

        stats = self.graph.stats()
        logger.info(f"[+] Graph built: {stats}")
        return self.graph

    # ------------------------------------------------------------------ #
    #  Node registration                                                   #
    # ------------------------------------------------------------------ #

    def _add_user_nodes(self, users: list[dict]):
        for u in users:
            node = NodeData(
                id=self._dn_to_id(u["dn"]),
                label=u["sam"],
                type="user",
                dn=u["dn"],
                properties={
                    "enabled": u.get("enabled", True),
                    "admin_count": u.get("admin_count", 0),
                    "kerberoastable": u.get("is_kerberoastable", False),
                    "asreproastable": u.get("no_preauth_required", False),
                    "password_never_expires": u.get("password_never_expires", False),
                    "spns": u.get("spns", []),
                    "email": u.get("email"),
                    "description": u.get("description"),
                }
            )
            self.graph.add_node(node)

    def _add_group_nodes(self, groups: list[dict]):
        for g in groups:
            node = NodeData(
                id=self._dn_to_id(g["dn"]),
                label=g["sam"],
                type="group",
                dn=g["dn"],
                properties={
                    "admin_count": g.get("admin_count", 0),
                    "description": g.get("description"),
                    "is_high_value": self._is_high_value_group(g["sam"]),
                }
            )
            self.graph.add_node(node)

    def _add_computer_nodes(self, computers: list[dict]):
        for c in computers:
            node = NodeData(
                id=self._dn_to_id(c["dn"]),
                label=c.get("dns_hostname") or c["sam"],
                type="computer",
                dn=c["dn"],
                properties={
                    "enabled": c.get("enabled", True),
                    "os": c.get("os"),
                    "os_version": c.get("os_version"),
                    "dns_hostname": c.get("dns_hostname"),
                }
            )
            self.graph.add_node(node)

    def _add_ou_nodes(self, ous: list[dict]):
        for ou in ous:
            node = NodeData(
                id=self._dn_to_id(ou["dn"]),
                label=ou["name"] or ou["dn"],
                type="ou",
                dn=ou["dn"],
                properties={"description": ou.get("description")}
            )
            self.graph.add_node(node)

    def _add_gpo_nodes(self, gpos: list[dict]):
        for gpo in gpos:
            node = NodeData(
                id=self._dn_to_id(gpo["dn"]),
                label=gpo.get("name") or gpo["dn"],
                type="gpo",
                dn=gpo["dn"],
                properties={"path": gpo.get("path")}
            )
            self.graph.add_node(node)

    # ------------------------------------------------------------------ #
    #  Edge construction                                                   #
    # ------------------------------------------------------------------ #

    def _add_membership_edges(self, memberships: list[tuple]):
        """
        (member_dn, group_dn) → MemberOf edge.
        Direction: member --MemberOf--> group
        """
        added = 0
        for member_dn, group_dn in memberships:
            src = self.graph.get_id_by_dn(member_dn)
            dst = self.graph.get_id_by_dn(group_dn)
            if src and dst:
                self.graph.add_edge(EdgeData(
                    src=src, dst=dst, relation="MemberOf"
                ))
                added += 1
            else:
                logger.debug(f"  [?] Unresolved membership: {member_dn} -> {group_dn}")

        logger.info(f"  [>] MemberOf edges added: {added}")

    def _add_session_edges(self, sessions, users: list[dict]):
        """
        Session data: user logged on to computer.
        Direction: user --HasSession--> computer
        """
        # Build sam -> node_id lookup
        sam_index = {
            u["sam"].lower(): self._dn_to_id(u["dn"])
            for u in users
        }

        # Build hostname -> node_id lookup
        host_index = {
            n.properties.get("dns_hostname", "").lower(): nid
            for nid, n in self.graph.nodes.items()
            if n.type == "computer"
        }

        added = 0
        for session in sessions:
            user_id = sam_index.get(session.logged_on_user.lower())
            computer_id = host_index.get(session.source_host.lower())

            if user_id and computer_id:
                self.graph.add_edge(EdgeData(
                    src=user_id,
                    dst=computer_id,
                    relation="HasSession",
                    properties={"client": session.client_name}
                ))
                added += 1

        logger.info(f"  [>] HasSession edges added: {added}")

    def _add_admin_edges(self, admins, computers: list[dict]):
        """
        Local admin data: principal is admin on computer.
        Direction: principal --AdminTo--> computer
        """
        # SID -> node_id (approximate; full resolution needs SID map)
        added = 0
        for admin in admins:
            # Find computer node
            computer_id = None
            for nid, n in self.graph.nodes.items():
                if n.type == "computer" and (
                    n.label.lower() == admin.computer.lower() or
                    n.properties.get("dns_hostname", "").lower() == admin.computer.lower()
                ):
                    computer_id = nid
                    break

            if computer_id and admin.member_dn:
                # Try to resolve member by DN first, then SID
                member_id = self.graph.get_id_by_dn(admin.member_dn)
                if member_id:
                    self.graph.add_edge(EdgeData(
                        src=member_id,
                        dst=computer_id,
                        relation="AdminTo"
                    ))
                    added += 1

        logger.info(f"  [>] AdminTo edges added: {added}")

    # ------------------------------------------------------------------ #
    #  Utilities                                                           #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _dn_to_id(dn: str) -> str:
        """Stable short ID from DN."""
        return hashlib.md5(dn.lower().encode()).hexdigest()[:16]

    @staticmethod
    def _is_high_value_group(sam: str) -> bool:
        """Flag well-known privileged groups."""
        HIGH_VALUE = {
            "domain admins", "enterprise admins", "schema admins",
            "administrators", "account operators", "backup operators",
            "print operators", "server operators", "group policy creator owners",
            "domain controllers", "read-only domain controllers",
        }
        return sam.lower() in HIGH_VALUE
