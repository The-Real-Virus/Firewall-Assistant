"""Administrator command contract. Implementations use Qt-free services."""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

from wfdiag.contracts.desktop_job import decode_request
from wfdiag.contracts.enums import Completeness
from wfdiag.errors import DiagnosticError, ExitCode
from wfdiag.services import operations
from wfdiag.services.cancellation import CancellationToken
from wfdiag.version import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wfdiag",
        description="Local Windows Firewall evidence diagnostics. Never applies firewall changes.",
    )
    parser.add_argument("--version", action="version", version=f"wfdiag {__version__}")
    commands = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="{doctor,collect,analyze,report,propose,compare}",
    )
    doctor = commands.add_parser("doctor", help="Check platform and evidence capabilities")
    doctor.add_argument("--out", required=True, help="New doctor JSON output file")
    collect = commands.add_parser("collect", help="Read a bounded local evidence window")
    collect.add_argument("--minutes", type=int, choices=range(1, 61), default=10, metavar="1..60")
    collect.add_argument("--out", required=True, help="New private case directory")
    analyze = commands.add_parser("analyze", help="Analyze a validated case offline")
    analyze.add_argument("--bundle", required=True)
    analyze.add_argument(
        "--intent", help="Verified intended flow JSON; optional for general findings"
    )
    analyze.add_argument("--out", required=True, help="New analysis directory")
    report = commands.add_parser("report", help="Export a static offline report")
    report.add_argument("--analysis", required=True)
    report.add_argument("--mode", required=True, choices=("share", "full"))
    report.add_argument("--out", required=True, help="New .html or .json report file")
    propose = commands.add_parser("propose", help="Export an eligible JSON review proposal")
    propose.add_argument("--analysis", required=True)
    propose.add_argument("--finding-id", required=True)
    propose.add_argument("--intent", required=True)
    propose.add_argument("--out", required=True, help="New non-executable proposal JSON file")
    compare = commands.add_parser("compare", help="Compare completed analyses and uncertainty")
    compare.add_argument("--before", required=True)
    compare.add_argument("--after", required=True)
    compare.add_argument("--out", required=True, help="New comparison JSON file")
    internal = commands.add_parser("desktop-job")
    internal.add_argument("--request", required=True)
    permission = commands.add_parser("permission-collect")
    permission.add_argument("--minutes", type=int, choices=range(1, 61), required=True)
    permission.add_argument("--out", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "desktop-job":
            from wfdiag.services.desktop_worker import run_desktop_job

            return run_desktop_job(Path(args.request).absolute())
        if args.command == "permission-collect":
            from wfdiag.services.permission_collection import permission_collect

            complete = permission_collect(Path(args.out).absolute(), args.minutes)
            return 0 if complete == Completeness.COMPLETE else 5
        parameters = {key: value for key, value in vars(args).items() if key != "command"}
        for key in ("out", "bundle", "analysis", "intent", "before", "after"):
            if parameters.get(key) is not None:
                parameters[key] = str(Path(parameters[key]).absolute())
        request = decode_request(
            json.dumps(
                {
                    "protocol_version": 1,
                    "job_id": str(uuid4()),
                    "operation": args.command,
                    "expected_engine_version": __version__,
                    "parameters": parameters,
                }
            ).encode("utf-8")
        )
        completeness = operations.execute(
            request, CancellationToken(), lambda stage, done, total: None
        )
        return int(
            ExitCode.COMPLETED if completeness == Completeness.COMPLETE else ExitCode.INCOMPLETE
        )
    except KeyboardInterrupt:
        print(
            "wfdiag: Operation interrupted; incomplete output may remain for review.",
            file=sys.stderr,
        )
        return int(ExitCode.INCOMPLETE)
    except DiagnosticError as exc:
        print(f"wfdiag: {exc.public_message}", file=sys.stderr)
        return int(exc.code)
    except ValueError:
        print("wfdiag: Invalid operation parameters. See command help.", file=sys.stderr)
        return int(ExitCode.INVALID_INPUT)
    except Exception:  # noqa: BLE001 -- Public process boundary must not disclose case data in a traceback.
        print(
            "wfdiag: Internal processing failure; no successful result was produced.",
            file=sys.stderr,
        )
        return int(ExitCode.INTERNAL)
