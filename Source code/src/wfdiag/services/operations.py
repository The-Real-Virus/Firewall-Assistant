"""Single local operation entry point used by the CLI and desktop adapter."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from wfdiag.analysis.compare import compare_analyses
from wfdiag.analysis.engine import analyze_case
from wfdiag.collectors.preflight import doctor, native_probe, observed_host
from wfdiag.contracts.desktop_job import DesktopRequest
from wfdiag.contracts.enums import Completeness, SourceState
from wfdiag.errors import DiagnosticError, ExitCode, OperationUnavailable
from wfdiag.parsers.firewall_log import parse_firewall_log
from wfdiag.proposals.generate import generate_proposal
from wfdiag.reporting.limits import report_byte_limit
from wfdiag.reporting.render import iter_report_chunks
from wfdiag.services.cancellation import CancellationToken
from wfdiag.services.interfaces import ProgressSink
from wfdiag.storage.analysis_json import analysis_json_chunks
from wfdiag.storage.atomic_write import write_new_bytes, write_new_chunks
from wfdiag.storage.bundle import VerifiedBundle
from wfdiag.storage.private_output import new_analysis_directory, private_parent
from wfdiag.storage.records import MAX_ANALYSIS_BYTES, read_analysis, read_intent
from wfdiag.version import __version__


def execute(
    request: DesktopRequest,
    cancellation: CancellationToken,
    progress: ProgressSink,
) -> Completeness:
    try:
        return _execute(request, cancellation, progress)
    except FileExistsError as exc:
        raise DiagnosticError(
            ExitCode.INVALID_INPUT, "Output exists; choose a new destination."
        ) from exc
    except FileNotFoundError as exc:
        raise DiagnosticError(
            ExitCode.INVALID_INPUT, "A required input or output parent does not exist."
        ) from exc
    except PermissionError as exc:
        raise DiagnosticError(
            ExitCode.ACCESS_DENIED,
            "Input access or verified private output is unavailable; choose an approved private location.",
        ) from exc
    except ValueError as exc:
        raise DiagnosticError(
            ExitCode.INVALID_INPUT,
            "Input format, output format or byte budget is invalid; no completed result was produced.",
        ) from exc
    except OSError as exc:
        raise DiagnosticError(
            ExitCode.INTERNAL,
            "Local storage or processing failed; no successful result was reported.",
        ) from exc


def _execute(
    request: DesktopRequest, cancellation: CancellationToken, progress: ProgressSink
) -> Completeness:
    cancellation.check()
    if request.expected_engine_version != __version__:
        raise DiagnosticError(
            ExitCode.INVALID_INPUT, "Engine version differs from the requested operation."
        )
    if request.operation == "collect":
        from wfdiag.collectors.capture import collect_native_case

        manifest = collect_native_case(
            Path(request.parameters.out), request.parameters.minutes, cancellation, progress
        )
        return manifest.completeness
    if request.operation == "analyze":
        parameters = request.parameters
        intent = read_intent(Path(parameters.intent)) if parameters.intent is not None else None
        progress("validate-input", 0, None)
        with VerifiedBundle(Path(parameters.bundle), cancellation) as bundle:
            progress("analyze", 0, None)
            log_status = next(
                (s for s in bundle.manifest.sources if s.source == "firewall-log"), None
            )
            text_log = (
                parse_firewall_log(bundle.iter_firewall_log_lines())
                if log_status is not None
                and log_status.state in (SourceState.COMPLETE, SourceState.EMPTY)
                else None
            )
            result = analyze_case(
                bundle.manifest,
                bundle.profiles,
                bundle.rules,
                bundle.iter_events(),
                intent=intent,
                network=bundle.network,
                analyzed_at_utc=datetime.now(UTC),
                cancellation=cancellation,
                firewall_log=text_log,
            )
            bundle.check_unchanged()
            cancellation.check()
            with new_analysis_directory(Path(parameters.out)) as directory:
                write_new_chunks(
                    directory / "analysis.json",
                    analysis_json_chunks(result, cancellation),
                    byte_limit=MAX_ANALYSIS_BYTES,
                )
                cancellation.check()
        return result.completeness
    if request.operation == "report":
        report_params = request.parameters
        destination = Path(report_params.out)
        suffix = destination.suffix.lower()
        if suffix not in (".html", ".json"):
            raise ValueError("Use an html or json report destination")
        format: Literal["html", "json"] = "html" if suffix == ".html" else "json"
        analysis = read_analysis(Path(report_params.analysis))
        cancellation.check()
        progress("render-report", 0, None)
        content = iter_report_chunks(
            analysis, mode=report_params.mode, format=format, cancellation=cancellation
        )
        if report_params.mode == "full":
            with private_parent(destination):
                write_new_chunks(destination, content, byte_limit=report_byte_limit(format))
        else:
            write_new_chunks(destination, content, byte_limit=report_byte_limit(format))
        return Completeness.COMPLETE
    if request.operation == "propose":
        proposal_params = request.parameters
        analysis = read_analysis(Path(proposal_params.analysis))
        intent = read_intent(Path(proposal_params.intent))
        proposal = generate_proposal(analysis, proposal_params.finding_id, intent)
        cancellation.check()
        destination = Path(proposal_params.out)
        with private_parent(destination):
            write_new_bytes(
                destination, (proposal.model_dump_json(indent=2) + "\n").encode("utf-8")
            )
        return Completeness.COMPLETE
    if request.operation == "compare":
        compare_params = request.parameters
        before, after = (
            read_analysis(Path(compare_params.before)),
            read_analysis(Path(compare_params.after)),
        )
        comparison_result = compare_analyses(before, after)
        cancellation.check()
        destination = Path(compare_params.out)
        with private_parent(destination):
            write_new_bytes(
                destination,
                (comparison_result.model_dump_json(indent=2) + "\n").encode("utf-8"),
                byte_limit=MAX_ANALYSIS_BYTES,
            )
        return Completeness.COMPLETE
    if request.operation == "doctor":
        report, code = doctor(observed_host(), native_probe, cancellation)
        cancellation.check()
        try:
            write_new_bytes(
                Path(request.parameters.out),
                (report.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
        except FileExistsError as exc:
            raise DiagnosticError(
                ExitCode.INVALID_INPUT, "Output exists; choose a new file."
            ) from exc
        except PermissionError as exc:
            raise DiagnosticError(
                ExitCode.ACCESS_DENIED, "The output location is not writable with current access."
            ) from exc
        except FileNotFoundError as exc:
            raise DiagnosticError(
                ExitCode.INVALID_INPUT, "Choose a new output file in an existing local folder."
            ) from exc
        except OSError as exc:
            raise DiagnosticError(
                ExitCode.INTERNAL, "Could not finalize the new preflight output."
            ) from exc
        if code != ExitCode.COMPLETED:
            raise DiagnosticError(
                code,
                "Preflight recorded unsupported, unavailable or denied collection capabilities. See the local doctor report.",
            )
        return Completeness.COMPLETE
    raise OperationUnavailable(request.operation)
