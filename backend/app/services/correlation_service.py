"""PS component 4: cross-case correlation via shared IP/domain infrastructure. No
generic graph database — just queries over IndicatorObservation (one row per IP/domain
seen per case). Always phrased as "potential correlation" / "shared infrastructure",
never "same attacker" — see PS section 13/27."""

from sqlmodel import Session, select

from app.models.case import Case
from app.models.correlation import IndicatorObservation


def find_shared_infrastructure(session: Session, case_id: int) -> list[dict]:
    """For every indicator (IP/domain) observed in this case, find which *other* cases
    also observed it."""
    this_case_indicators = session.exec(
        select(IndicatorObservation.indicator_type, IndicatorObservation.indicator_value)
        .where(IndicatorObservation.case_id == case_id)
        .distinct()
    ).all()

    shared = []
    for indicator_type, indicator_value in this_case_indicators:
        other_case_ids = session.exec(
            select(IndicatorObservation.case_id)
            .where(
                IndicatorObservation.indicator_type == indicator_type,
                IndicatorObservation.indicator_value == indicator_value,
                IndicatorObservation.case_id != case_id,
            )
            .distinct()
        ).all()
        if other_case_ids:
            shared.append(
                {
                    "indicator_type": indicator_type,
                    "indicator_value": indicator_value,
                    "other_case_ids": sorted(set(other_case_ids)),
                    "note": "Potential shared infrastructure detected — this does not confirm the same actor.",
                }
            )
    return shared


def build_case_graph(session: Session, case_id: int) -> dict:
    """Nodes/edges for the frontend correlation graph: this case's own indicator
    nodes, plus edges out to *other* cases that share one of those indicators."""
    if session.get(Case, case_id) is None:
        return {"nodes": [], "edges": []}

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_node(node_id: str, node_type: str, label: str) -> None:
        nodes.setdefault(node_id, {"id": node_id, "type": node_type, "label": label})

    case_node_id = f"case:{case_id}"
    add_node(case_node_id, "case", f"Case #{case_id}")

    observations = session.exec(select(IndicatorObservation).where(IndicatorObservation.case_id == case_id)).all()

    for obs in observations:
        indicator_node_id = f"{obs.indicator_type}:{obs.indicator_value}"
        add_node(indicator_node_id, obs.indicator_type, obs.indicator_value)
        edges.append({"source": case_node_id, "target": indicator_node_id, "relationship": "observed_in"})

        other_case_ids = session.exec(
            select(IndicatorObservation.case_id)
            .where(
                IndicatorObservation.indicator_type == obs.indicator_type,
                IndicatorObservation.indicator_value == obs.indicator_value,
                IndicatorObservation.case_id != case_id,
            )
            .distinct()
        ).all()
        for other_case_id in set(other_case_ids):
            other_node_id = f"case:{other_case_id}"
            add_node(other_node_id, "case", f"Case #{other_case_id}")
            edges.append(
                {"source": indicator_node_id, "target": other_node_id, "relationship": "potential_correlation"}
            )

    return {"nodes": list(nodes.values()), "edges": edges}
