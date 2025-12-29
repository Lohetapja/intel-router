import json
import ipaddress
from datetime import datetime

NOW = datetime.now()

# Opinionated, narrow constants
HIGH_CONFIDENCE_SOURCES = {"abuse_ch"}

# Conservative noise exclusions (SOC hygiene)
IGNORE_SOURCES = set()
IGNORE_DOMAINS_SUFFIX = {".local", ".lan"}
IGNORE_DOMAINS_EXACT = {"localhost"}


def is_private_or_local_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
        )
    except ValueError:
        return False


def is_noise(item: dict) -> tuple[bool, str]:
    """
    Returns (True, reason) if the indicator is obvious noise.
    Keep this conservative and explainable.
    """
    src = item.get("source", "")
    if src in IGNORE_SOURCES:
        return True, f"Ignored source: {src}"

    ioc = item.get("indicator", "")
    ioc_type = item.get("type", "")

    if ioc_type == "ip" and is_private_or_local_ip(ioc):
        return True, "Private/local IP (not actionable for external threat intel)"

    if ioc_type == "domain":
        low = ioc.lower()
        if low in IGNORE_DOMAINS_EXACT:
            return True, "Localhost domain (noise)"
        for suf in IGNORE_DOMAINS_SUFFIX:
            if low.endswith(suf):
                return True, f"Local domain suffix (noise): {suf}"

    return False, ""


def confidence_decay(age_days: int) -> float:
    """
    Simple, explainable confidence decay based ONLY on time.

    0 days   -> 1.00
    7 days   -> ~0.80
    30 days  -> ~0.30
    60+ days -> ~0.10 (floor)

    This is not 'truth' — it's a relative signal.
    """
    if age_days <= 0:
        return 1.0

    score = 1.0 / (1.0 + (age_days / 10.0))
    return round(max(score, 0.10), 2)


def hunt_queries(item: dict) -> dict:
    """Generic hunt query templates (no integrations)."""
    ioc = item.get("indicator")
    ioc_type = item.get("type")

    if ioc_type == "ip":
        return {
            "splunk": f'(src_ip="{ioc}" OR dest_ip="{ioc}" OR ip="{ioc}") earliest=-30d',
            "kql": f'SecurityEvent | where IpAddress == "{ioc}" or DestinationIp == "{ioc}" or SourceIp == "{ioc}"',
            "generic": f"Search logs for IP == {ioc} (src/dst/any) last 30 days",
        }

    if ioc_type == "domain":
        return {
            "splunk": f'(query="{ioc}" OR domain="{ioc}" OR url="*{ioc}*") earliest=-30d',
            "kql": f'DnsEvents | where Name has "{ioc}"',
            "generic": f"Search DNS/proxy logs for domain contains {ioc} last 30 days",
        }

    return {}


def route_indicator(item: dict) -> dict:
    last_seen = datetime.fromisoformat(item["last_seen"])
    age_days = (NOW - last_seen).days
    confidence = confidence_decay(age_days)

    ignored, ignore_reason = is_noise(item)
    if ignored:
        return {
            "indicator": item.get("indicator"),
            "type": item.get("type"),
            "source": item.get("source"),
            "last_seen": item.get("last_seen"),
            "age_days": age_days,
            "confidence": confidence,
            "bucket": "IGNORED",
            "reason": ignore_reason,
        }

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

    result = {
        "indicator": item.get("indicator"),
        "type": item.get("type"),
        "source": item.get("source"),
        "last_seen": item.get("last_seen"),
        "age_days": age_days,
        "confidence": confidence,
        "bucket": bucket,
        "reason": reason,
    }

    if bucket == "HUNT":
        result["hunt"] = {
            "hypothesis": "IOC may have interacted with internal environment (verify in logs).",
            "queries": hunt_queries(item),
        }

    return result


def main() -> None:
    print("intel-router started")

    with open("intel.json", "r", encoding="utf-8") as f:
        intel = json.load(f)

    routed = [route_indicator(x) for x in intel]

    report = {
        "generated_at": NOW.isoformat(timespec="seconds"),
        "counts": {
            "total": len(routed),
            "ignored": sum(1 for r in routed if r["bucket"] == "IGNORED"),
            "block": sum(1 for r in routed if r["bucket"] == "BLOCK"),
            "hunt": sum(1 for r in routed if r["bucket"] == "HUNT"),
            "awareness": sum(1 for r in routed if r["bucket"] == "AWARENESS"),
        },
        "ignored": [r for r in routed if r["bucket"] == "IGNORED"],
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
