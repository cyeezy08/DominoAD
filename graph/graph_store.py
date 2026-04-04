"""
graph_store.py
--------------
Save and load the ADGraph to/from JSON.
Also exports to adjacency list format for the BFS engine.
"""

import json
import logging
from pathlib import Path
from graph_builder import ADGraph, NodeData, EdgeData

logger = logging.getLogger(__name__)


class GraphStore:

    @staticmethod
    def save(graph: ADGraph, path: str):
        """Serialize graph to JSON."""
        data = {
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label,
                    "type": n.type,
                    "dn": n.dn,
                    "properties": n.properties
                }
                for n in graph.nodes.values()
            ],
            "edges": [
                {
                    "src": e.src,
                    "dst": e.dst,
                    "relation": e.relation,
                    "properties": e.properties
                }
                for e in graph.edges
            ]
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info(f"[+] Graph saved to {path} "
                    f"({len(data['nodes'])} nodes, {len(data['edges'])} edges)")

    @staticmethod
    def load(path: str) -> ADGraph:
        """Load graph from JSON."""
        with open(path) as f:
            data = json.load(f)

        graph = ADGraph()
        for n in data["nodes"]:
            graph.add_node(NodeData(
                id=n["id"],
                label=n["label"],
                type=n["type"],
                dn=n["dn"],
                properties=n.get("properties", {})
            ))
        for e in data["edges"]:
            graph.add_edge(EdgeData(
                src=e["src"],
                dst=e["dst"],
                relation=e["relation"],
                properties=e.get("properties", {})
            ))

        logger.info(f"[+] Graph loaded from {path} "
                    f"({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
        return graph

    @staticmethod
    def to_adjacency(graph: ADGraph, relations: list[str] = None) -> dict[str, list[str]]:
        """
        Export graph as adjacency list for BFS engine.
        Optionally filter by edge relation types.

        Returns: { node_id: [neighbor_id, ...] }
        """
        adj: dict[str, list[str]] = {nid: [] for nid in graph.nodes}

        for edge in graph.edges:
            if relations and edge.relation not in relations:
                continue
            if edge.src in adj:
                adj[edge.src].append(edge.dst)

        return adj

    @staticmethod
    def export_summary(graph: ADGraph) -> dict:
        """Human-readable summary of the graph."""
        from collections import Counter

        kerberoastable = [
            n.label for n in graph.nodes.values()
            if n.type == "user" and n.properties.get("kerberoastable")
        ]
        asreproastable = [
            n.label for n in graph.nodes.values()
            if n.type == "user" and n.properties.get("asreproastable")
        ]
        high_value_groups = [
            n.label for n in graph.nodes.values()
            if n.type == "group" and n.properties.get("is_high_value")
        ]
        disabled_users = [
            n.label for n in graph.nodes.values()
            if n.type == "user" and not n.properties.get("enabled", True)
        ]

        return {
            "totals": graph.stats(),
            "kerberoastable_users": kerberoastable,
            "asreproastable_users": asreproastable,
            "high_value_groups": high_value_groups,
            "disabled_accounts": disabled_users,
        }
