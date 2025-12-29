import json
from datetime import datetime

NOW = datetime.now()
HIGH_CONFIDENCE_SOURCES = {"abuse_ch"}

def route_indicator(item: dict) -> dict:
    """Return a routed result for one indicator with explainable reasoning."""
    last_seen = datetime.fromisoformat(item["last_seen"])
    age_days = (NOW - last_seen).days

    if (
        age_days <= 7
        and item.get("type") == "ip"
        and item.get("source") in HIGH_CONFIDENCE_SOURCES
    ):
        bucket = "BLOCK"
        reason = "Recent IP from high-confidence source"
    elif age_days <= 30:
        bucket = "HUNT"
        reason = "Seen within last 30 days"
    else:
        bucket = "AWARENESS"
        reason = "Indicator is older than 30 days"

    return {
        "indicator": item.get("indicator"),
        "type": item.get("type"),
        "source": item.get("source"),
        "last_seen": item.get("last_seen"),
        "age_days": age_days,
        "bucket": bucket,
        "reason": reason,
    }

def main() -> None:
    print("intel-router started")

    with open("intel.json", "r", encoding="utf-8") as f:
        intel = json.load(f)

    routed = [route_indicator(x) for x in intel]

    report = {
        "generated_at": NOW.isoformat(timespec="seconds"),
        "counts": {
            "total": len(routed),
            "block": sum(1 for r in routed if r["bucket"] == "BLOCK"),
            "hunt": sum(1 for r in routed if r["bucket"] == "HUNT"),
            "awareness": sum(1 for r in routed if r["bucket"] == "AWARENESS"),
        },
        "block_candidates": [r for r in routed if r["bucket"] == "BLOCK"],
        "hunt_packages": [r for r in routed if r["bucket"] == "HUNT"],
        "awareness": [r for r in routed if r["bucket"] == "AWARENESS"],
    }

    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Loaded {len(intel)} indicators")
    print("Wrote report.json")

if __name__ == "__main__":
    main()
