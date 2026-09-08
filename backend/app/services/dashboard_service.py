"""PS component 18: dashboard aggregate statistics."""

from collections import Counter
from datetime import datetime, timezone

from sqlmodel import Session, select

from app.models.case import Case, DetectionResult
from app.models.correlation import IndicatorObservation
from app.services.scoring_config import CLASSIFICATION_BANDS

_HIGH_RISK_THRESHOLD = CLASSIFICATION_BANDS["phishing"][0]  # 60
_CRITICAL_THRESHOLD = CLASSIFICATION_BANDS["fraud"][0]  # 80


def get_dashboard_stats(session: Session) -> dict:
    cases = session.exec(select(Case)).all()
    detections = session.exec(select(DetectionResult)).all()

    today = datetime.now(timezone.utc).date()
    investigations_today = sum(1 for c in cases if c.created_at.date() == today)

    indicator_rows = session.exec(select(IndicatorObservation.indicator_value, IndicatorObservation.case_id)).all()
    value_to_cases: dict[str, set[int]] = {}
    for value, case_id in indicator_rows:
        value_to_cases.setdefault(value, set()).add(case_id)
    potential_campaigns = sum(1 for case_ids in value_to_cases.values() if len(case_ids) > 1)

    recent_cases = sorted(cases, key=lambda c: c.created_at, reverse=True)[:5]

    return {
        "total_cases": len(cases),
        "high_risk_count": sum(1 for d in detections if d.fraud_score >= _HIGH_RISK_THRESHOLD),
        "critical_count": sum(1 for d in detections if d.fraud_score >= _CRITICAL_THRESHOLD),
        "potential_campaigns": potential_campaigns,
        "investigations_today": investigations_today,
        "classification_breakdown": dict(Counter(d.classification_label for d in detections)),
        "threat_category_breakdown": dict(Counter(d.threat_category for d in detections)),
        "recent_cases": [
            {
                "id": c.id,
                "title": c.title,
                "overall_risk_level": c.overall_risk_level,
                "status": c.status,
                "created_at": c.created_at.isoformat(),
            }
            for c in recent_cases
        ],
    }
