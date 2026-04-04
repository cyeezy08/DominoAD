"""
bfs_engine.py
-------------
Attack path analysis on the AD graph using BFS.

Core questions it answers:
  1. Can [user] reach Domain Admins? What's the shortest path?
  2. Which users have ANY path to a high-value target?
  3. What's the blast radius from a compromised account?
  4. Which nodes are on the most attack paths? (chokepoints)

Edge relations traversed (by default):
  MemberOf | AdminTo | HasSession

Logic:
  - MemberOf:   if you're in group X, you inherit X's edges
  - AdminTo:    if you're admin on a computer, you can move to it
  - HasSession: if a privileged user has a session on a machine
                you control, you can potentially steal their creds
"""

import logging
from collections import deque, defaultdict
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Edge relations that represent lateral movement / privilege escalation
TRAVERSABLE = {"MemberOf", "AdminTo", "HasSession"}


@dataclass
class AttackPath:
    src_id: str
    dst_id: str
    src_label: str
    dst_label: str
    path_ids: list[str]       # node IDs along path
    path_labels: list[str]    # human-readable
    path_edges: list[str]     # edge relations along path
    length: int


class BFSEngine:
    def __init__(self, graph):
        """
        graph: ADGraph from graph_builder.py
        """
        self.graph = graph
        # Build adjacency list with edge labels:
        # adj[src] = [(dst, relation), ...]
        self.adj: dict[str, list[tuple]] = defaultdict(list)
        for edge in graph.edges:
            if edge.relation in TRAVERSABLE:
                self.adj[edge.src].append((edge.dst, edge.relation))

    # ------------------------------------------------------------------ #
    #  Core BFS                                                            #
    # ------------------------------------------------------------------ #

    def shortest_path(self, src_id: str, dst_id: str) -> Optional[AttackPath]:
        """
        BFS from src to dst.
        Returns shortest AttackPath or None if unreachable.
        """
        if src_id == dst_id:
            return None
        if src_id not in self.graph.nodes or dst_id not in self.graph.nodes:
            return None

        # BFS state: (current_id, path_ids, path_edges)
        queue = deque([(src_id, [src_id], [])])
        visited = {src_id}

        while queue:
            current, path, edges = queue.popleft()

            for neighbor, relation in self.adj.get(current, []):
                if neighbor in visited:
                    continue

                new_path = path + [neighbor]
                new_edges = edges + [relation]

                if neighbor == dst_id:
                    return self._make_path(src_id, dst_id, new_path, new_edges)

                visited.add(neighbor)
                queue.append((neighbor, new_path, new_edges))

        return None  # no path found

    def all_paths_to(self, dst_id: str, max_depth: int = 6) -> list[AttackPath]:
        """
        Find ALL nodes that can reach dst_id within max_depth hops.
        Returns list of AttackPath sorted by length.

        Useful for: "who can reach Domain Admins?"
        """
        if dst_id not in self.graph.nodes:
            return []

        results = []
        visited_sources = set()

        # BFS backwards from dst using reverse adjacency
        rev_adj = self._build_reverse_adj()

        queue = deque([(dst_id, [dst_id], [], 0)])
        seen = {dst_id}

        while queue:
            current, path, edges, depth = queue.popleft()

            if depth >= max_depth:
                continue

            for neighbor, relation in rev_adj.get(current, []):
                if neighbor in seen:
                    continue
                seen.add(neighbor)

                new_path = [neighbor] + path
                new_edges = [relation] + edges

                # Every node we find is a valid source
                if neighbor != dst_id:
                    ap = self._make_path(neighbor, dst_id, new_path, new_edges)
                    results.append(ap)

                queue.append((neighbor, new_path, new_edges, depth + 1))

        results.sort(key=lambda x: x.length)
        return results

    def blast_radius(self, src_id: str, max_depth: int = 6) -> list[str]:
        """
        BFS forward from src. Returns all reachable node IDs.
        Useful for: "if this account is compromised, what's reachable?"
        """
        if src_id not in self.graph.nodes:
            return []

        visited = {src_id}
        queue = deque([(src_id, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for neighbor, _ in self.adj.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, depth + 1))

        visited.discard(src_id)
        return list(visited)

    # ------------------------------------------------------------------ #
    #  High-level queries                                                  #
    # ------------------------------------------------------------------ #

    def find_da_paths(self) -> list[AttackPath]:
        """
        Find all paths to Domain Admins group.
        The flagship query — equivalent to BloodHound's 'Shortest Paths to DA'.
        """
        da_id = self._find_node_by_label("Domain Admins", node_type="group")
        if not da_id:
            logger.warning("[-] 'Domain Admins' group not found in graph")
            return []

        paths = self.all_paths_to(da_id)
        logger.info(f"[+] Paths to Domain Admins: {len(paths)}")
        return paths

    def find_paths_between(self, src_label: str, dst_label: str) -> Optional[AttackPath]:
        """Convenience: find path by label instead of ID."""
        src_id = self._find_node_by_label(src_label)
        dst_id = self._find_node_by_label(dst_label)
        if not src_id:
            logger.warning(f"[-] Source not found: {src_label}")
            return None
        if not dst_id:
            logger.warning(f"[-] Destination not found: {dst_label}")
            return None
        return self.shortest_path(src_id, dst_id)

    def find_chokepoints(self, target_id: str = None) -> list[tuple]:
        """
        Find nodes that appear on the most attack paths to target.
        High chokepoint score = high-value lateral movement node.

        Returns: [(node_id, count)] sorted by count desc
        """
        if not target_id:
            da_id = self._find_node_by_label("Domain Admins", node_type="group")
            target_id = da_id

        if not target_id:
            return []

        paths = self.all_paths_to(target_id)
        counts: dict[str, int] = defaultdict(int)

        for path in paths:
            # Count intermediate nodes (not source or dest)
            for node_id in path.path_ids[1:-1]:
                counts[node_id] += 1

        ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        return ranked

    def kerberoastable_to_da(self) -> list[AttackPath]:
        """
        Find kerberoastable users that have a path to Domain Admins.
        High-priority finding for a report.
        """
        kerberoastable = [
            nid for nid, n in self.graph.nodes.items()
            if n.type == "user" and n.properties.get("kerberoastable")
        ]

        da_id = self._find_node_by_label("Domain Admins", node_type="group")
        if not da_id:
            return []

        paths = []
        for uid in kerberoastable:
            path = self.shortest_path(uid, da_id)
            if path:
                paths.append(path)

        paths.sort(key=lambda x: x.length)
        logger.info(f"[+] Kerberoastable users with path to DA: {len(paths)}")
        return paths

    def asreproastable_to_da(self) -> list[AttackPath]:
        """Find ASREPRoastable users with path to Domain Admins."""
        targets = [
            nid for nid, n in self.graph.nodes.items()
            if n.type == "user" and n.properties.get("asreproastable")
        ]
        da_id = self._find_node_by_label("Domain Admins", node_type="group")
        if not da_id:
            return []

        paths = []
        for uid in targets:
            path = self.shortest_path(uid, da_id)
            if path:
                paths.append(path)

        paths.sort(key=lambda x: x.length)
        return paths

    # ------------------------------------------------------------------ #
    #  Utilities                                                           #
    # ------------------------------------------------------------------ #

    def _make_path(self, src_id, dst_id, path_ids, path_edges) -> AttackPath:
        def label(nid):
            return self.graph.nodes.get(nid, type("", (), {"label": nid})()).label

        return AttackPath(
            src_id=src_id,
            dst_id=dst_id,
            src_label=label(src_id),
            dst_label=label(dst_id),
            path_ids=path_ids,
            path_labels=[label(n) for n in path_ids],
            path_edges=path_edges,
            length=len(path_ids) - 1
        )

    def _build_reverse_adj(self) -> dict[str, list[tuple]]:
        """Reverse adjacency list for backwards BFS."""
        rev = defaultdict(list)
        for src, neighbors in self.adj.items():
            for dst, relation in neighbors:
                rev[dst].append((src, relation))
        return rev

    def _find_node_by_label(self, label: str, node_type: str = None) -> Optional[str]:
        """Find node ID by label (case-insensitive)."""
        label_lower = label.lower()
        for nid, node in self.graph.nodes.items():
            if node.label.lower() == label_lower:
                if node_type and node.type != node_type:
                    continue
                return nid
        return None
