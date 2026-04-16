from typing import Any

import networkx as nx


def find_impacted_modules(graph: nx.DiGraph, start_node: str) -> list[dict[str, Any]]:
    if start_node not in graph:
        return []
    impacted: list[dict[str, Any]] = []
    for node in graph.nodes():
        if node == start_node:
            continue
        try:
            path = nx.shortest_path(graph, start_node, node)
        except nx.NetworkXNoPath:
            continue
        if len(path) > 1:
            impacted.append({"target": str(node), "path": [str(p) for p in path]})
    return impacted

