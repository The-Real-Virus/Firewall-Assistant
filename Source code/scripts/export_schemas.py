"""Generate or check shipped schemas from actual models in the installed package."""

import argparse
import json
from pathlib import Path

from wfdiag.ai.contracts import AiContext, AiRequest, Consent, Explanation
from wfdiag.collectors.protocol import FRAME_ADAPTER
from wfdiag.contracts.comparison import Comparison
from wfdiag.contracts.desktop_job import EVENT_ADAPTER, REQUEST_ADAPTER
from wfdiag.contracts.doctor import DoctorReport
from wfdiag.contracts.models import (
    Analysis,
    CollectionError,
    Event,
    FirewallProfile,
    Host,
    Intent,
    Manifest,
    NetworkSnapshot,
    Proposal,
    Rule,
    SourceStatus,
    TextLogResult,
)
from wfdiag.reporting.share import ShareReport


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1] / "src/wfdiag/resources/schemas"
    schemas = {
        "native-collector-frame-v1": FRAME_ADAPTER.json_schema(),
        "comparison-v1": Comparison.model_json_schema(),
        "firewall-text-log-v1": TextLogResult.model_json_schema(),
        "doctor-v1": DoctorReport.model_json_schema(),
        "network-v1": NetworkSnapshot.model_json_schema(),
        "collection-error-v1": CollectionError.model_json_schema(),
        "profile-v1": FirewallProfile.model_json_schema(),
        "share-report-v1": ShareReport.model_json_schema(),
        "manifest-v1": Manifest.model_json_schema(),
        "intent-v1": Intent.model_json_schema(),
        "analysis-v1": Analysis.model_json_schema(),
        "proposal-v1": Proposal.model_json_schema(),
        "event-v1": Event.model_json_schema(),
        "host-v1": Host.model_json_schema(),
        "rule-v1": Rule.model_json_schema(),
        "source-status-v1": SourceStatus.model_json_schema(),
        "desktop-request-v1": REQUEST_ADAPTER.json_schema(),
        "desktop-event-v1": EVENT_ADAPTER.json_schema(),
        "ai-context-v1": AiContext.model_json_schema(),
        "ai-request-v1": AiRequest.model_json_schema(),
        "ai-consent-v1": Consent.model_json_schema(),
        "ai-explanation-v1": Explanation.model_json_schema(),
    }
    for name, schema in schemas.items():
        path = root / f"{name}.schema.json"
        content = json.dumps(schema, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                print(f"Schema differs: {path.name}")
                return 1
        else:
            root.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    print(f"{'Checked' if args.check else 'Generated'} {len(schemas)} schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
