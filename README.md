## Design Principles

intel-router is intentionally narrow and conservative.

It is designed to support human SOC decision-making, not replace it.

Key principles:

- **Action-oriented**: Outputs recommendations (Block / Hunt / Awareness / Ignored), not raw intel.
- **Time-aware**: Indicator relevance decays over time; stale intel is de-prioritized.
- **Explainable**: Every routing decision includes a human-readable reason.
- **Noise-resistant**: Obvious non-actionable indicators (e.g., private IPs, localhost) are ignored early.
- **Non-automated**: No auto-blocking or enforcement is performed.
- **Opinionated**: Defaults are intentionally conservative and not endlessly configurable.

This tool favors clarity and restraint over completeness.
