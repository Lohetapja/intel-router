import json
from datetime import datetime, timedelta

print("intel-router started")

with open("intel.json", "r") as f:
    intel = json.load(f)

print(f"Loaded {len(intel)} indicators")

NOW = datetime.now()

for item in intel:
    last_seen = datetime.fromisoformat(item["last_seen"])
    age_days = (NOW - last_seen).days

    if age_days <= 30:
        bucket = "HUNT"
        reason = "Seen within last 30 days"
    else:
        bucket = "AWARENESS"
        reason = "Indicator is older than 30 days"

    print({
        "indicator": item["indicator"],
        "bucket": bucket,
        "age_days": age_days,
        "reason": reason
    })
