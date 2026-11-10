"""Read fixed collector files with the Windows PowerShell parser; never execute them."""

import json
import re
import subprocess
import sys
from pathlib import Path

from wfdiag.collectors.windows import system_directory

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    if sys.platform != "win32":
        raise RuntimeError("Collector baseline parsing requires Windows PowerShell5.1")
    executable = system_directory() / "WindowsPowerShell/v1.0/powershell.exe"
    # Paths enter the parser as single-quoted data, never as executable source.
    resources = ROOT / "src/wfdiag/resources/powershell"
    literal = str(resources).replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop';$results=@();$parseFailed=$false;"
        f"$files=@(Get-ChildItem -LiteralPath '{literal}' -Filter '*.ps1' -File);"
        "if($files.Count -ne 5){exit 2};foreach($file in $files){"
        "$tokens=$null;$errors=$null;"
        "[System.Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)|Out-Null;"
        "$results+=@{file=$file.Name;errors=@($errors).Count};if(@($errors).Count){$parseFailed=$true}};"
        "$results|ConvertTo-Json -Compress;"
        "if($parseFailed){exit 1}"
    )
    result = subprocess.run(
        [str(executable), "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode:
        identifiers = re.findall(
            r"FullyQualifiedErrorId\s*:\s*([A-Za-z0-9_,.]+)", result.stderr.decode(errors="replace")
        )
        print(
            json.dumps(
                {
                    "status": "collector_parser_failed",
                    "return_code": result.returncode,
                    "identifiers": identifiers,
                    "output": result.stdout.decode(errors="replace")[:4096],
                }
            )
        )
        return 1
    parsed = json.loads(result.stdout.decode("utf-8-sig"))
    if len(parsed) != 5 or any(row["errors"] for row in parsed):
        return 1
    print("Windows PowerShell5.1 parsed5 fixed collection files; no resource executed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
