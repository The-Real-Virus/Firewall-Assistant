import subprocess
import sys
from pathlib import Path


def test_core_imports_and_help_work_without_qt_httpx_or_network() -> None:
    code = """
import builtins, socket, sys
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.startswith(('PySide6','httpx','wfdiag.ai','wfdiag.gui')):
        raise AssertionError('Optional module imported by core: '+name)
    return original(name,*args,**kwargs)
def network_forbidden(*args,**kwargs):
    raise AssertionError('Network attempted by offline core')
builtins.__import__=guarded
socket.socket.connect=network_forbidden
socket.getaddrinfo=network_forbidden
import wfdiag.contracts.models
import wfdiag.contracts.desktop_job
import wfdiag.services.interfaces
from wfdiag.cli import main
try:
    main(['--help'])
except SystemExit as result:
    assert result.code == 0
else:
    raise AssertionError('Expected help exit')
"""
    result = subprocess.run(
        [sys.executable, "-c", code], check=False, capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0, result.stderr
    assert "Local Windows Firewall" in result.stdout


def test_imported_case_workflow_without_ai_qt_or_network(tmp_path: Path) -> None:
    """Actual core services; explicit privacy double, never native ACL acceptance."""
    code = r"""
import builtins, json, socket, sys
from pathlib import Path
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.startswith(('PySide6','httpx','wfdiag.ai','wfdiag.gui')):
        raise AssertionError('Optional module imported by core: '+name)
    return original(name,*args,**kwargs)
def network_forbidden(*args,**kwargs):
    raise AssertionError('Network attempted by offline imported-case workflow')
builtins.__import__=guarded
socket.socket.connect=network_forbidden
socket.socket.connect_ex=network_forbidden
socket.socket.sendto=network_forbidden
socket.getaddrinfo=network_forbidden
from wfdiag.cli import main
from wfdiag.storage import private_output
from wfdiag.storage.records import read_analysis
# Only filesystem privacy is doubled. All bundle validators, engine, proposal,
# redaction and comparison functions are real. Nothing probes native policy/access.
private_output.create_private_directory=lambda path: path.mkdir()
private_output.verify_private_directory=lambda path: None
examples=Path(sys.argv[1]); out=Path(sys.argv[2]); analysis=out/'analysis'
intent=examples/'intent-synthetic-confirmed.json'
assert main(['analyze','--bundle',str(examples/'synthetic-case'),
             '--intent',str(intent),'--out',str(analysis)])==0
result=read_analysis(analysis)
assert len(result.findings)==1 and result.findings[0].proposal_eligible
for mode in ('share','full'):
    for format in ('html','json'):
        assert main(['report','--analysis',str(analysis),'--mode',mode,
                     '--out',str(out/(mode+'.'+format))])==0
proposal=out/'proposal.json'
assert main(['propose','--analysis',str(analysis),'--finding-id',result.findings[0].finding_id,
             '--intent',str(intent),'--out',str(proposal)])==0
assert json.loads(proposal.read_text('utf-8'))['executable'] is False
comparison=out/'comparison.json'
assert main(['compare','--before',str(analysis),'--after',str(analysis),
             '--out',str(comparison)])==0
assert comparison.exists()
assert read_analysis(analysis)==result
print('Offline imported-case workflow completed; privacy boundary explicitly doubled')
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            code,
            str(Path(__file__).parents[2] / "examples"),
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "Offline imported-case workflow completed" in result.stdout
