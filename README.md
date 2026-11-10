# 🚀 Firewall Assistant 🚀  

Firewall Assistant helps you investigate why a Windows application cannot connect. The desktop application and administrator CLI share one diagnostic engine. Evidence collection, analysis, reports, and the sample case work offline. The optional AI Assistant starts off and can explain findings and carry out supported application actions after you connect a provider.

[User handbook](Documentation.docx) · [Rebuild from source](Docs/REBUILD.md) · [CLI reference](Docs/cli.md) · [Releases](https://github.com/random4web/Firewall-Assistant/releases)

## Repository layout

| Path | What it contains |
| --- | --- |
| [Source code/src/wfdiag](Source%20code/src/wfdiag/) | Diagnostic engine, Windows collectors, CLI, desktop interface, and optional AI Assistant |
| [Source code/tests](Source%20code/tests/) and [Source code/examples](Source%20code/examples/) | Automated tests and synthetic cases |
| [Source code/scripts](Source%20code/scripts/) and [Source code/packaging](Source%20code/packaging/) | Quality checks, build and verification tools, and Windows packaging definitions |
| [Source code/prepare_build.py](Source%20code/prepare_build.py) | Creates an isolated workspace for the Windows build |
| [Docs](Docs/) | User and developer documentation, exact dependency locks, technical specifications, and validation records |
| [Documentation.docx](Documentation.docx) | Complete user handbook |

The runnable Windows ZIP, checksum list, and package manifest go in GitHub Releases.

## Run the Windows app

1. Download the Windows x64 ZIP and `SHA256SUMS` from the release page. Use `Get-FileHash -Algorithm SHA256` in PowerShell to compare the ZIP against the matching line.
2. Extract the complete ZIP to a local folder. Keep `FirewallAssistant.exe`, `wfdiag.exe`, and their bundled folders together.
3. Open `FirewallAssistant.exe`. Select **Open example** to learn the findings, evidence, and report controls using synthetic data.
4. For a real investigation, reproduce the connection failure, then choose **Investigate a connection** and **Start investigation**. Choose general review if you are unsure of the intended connection details.
5. If Windows denies access to blocking events, choose whether to request permission for the separate read-only collector or continue with limited evidence. The findings explain the evidence gap. Reports and comparisons are available from the saved result.

The package targets x64 Windows 10 1809 or later and Windows 11 desktop editions. See the supported configurations and the verified coverage for the package. [Installation](Docs/installation.md) · [Support matrix](Docs/support-matrix.md) · [Known limitations](Docs/known-limitations.md)

Open a terminal inside the extracted package to try the CLI with synthetic data.

```powershell
.\wfdiag.exe --help
.\wfdiag.exe report --analysis .\examples\expected-analysis.json --mode share --out .\report-share.html
```

## Optional AI Assistant

Open **AI Assistant**, choose **Enable AI**, select a provider, enter its API key in the masked field, and choose **Connect & test**. After connecting, try asking it to open the example and explain a finding. The diagnostic engine produces the findings, and the cloud assistant works within the app's diagnostic actions and your current permissions. [AI setup](Docs/ai/setup.md) · [Provider details](Docs/ai/providers.md) · [Privacy and local data](Docs/privacy.md)

## Read, test, and rebuild the code

Start with the architecture and CLI documents. Read `src/wfdiag/cli.py` for the command entry point, `src/wfdiag/gui/launcher.py` for desktop startup, and `src/wfdiag/services/` for operations shared by both. Use the data contracts and collector documentation to understand how raw observations become typed evidence and findings. [Architecture](Docs/architecture.md) · [Data contracts](Docs/data-contracts.md) · [Windows collectors](Docs/collectors.md)

The rebuild guide walks through the required Windows and Python setup, copying the inputs into a separate build workspace, installing exact dependencies, running tests, compiling both executables, and checking the generated ZIP. [Complete rebuild guide](Docs/REBUILD.md) · [Dependency locks](Docs/dependencies.md) · [Packaging internals](Docs/packaging.md)

## Contribute and get support

Use an invented example or sanitized summary for bugs. Include the app version, Windows build, and steps to reproduce. Use the private reporting instructions for security findings and keep raw evidence and credentials in your local workspace. [Contributing](Docs/CONTRIBUTING.md) · [Security reporting](Docs/SECURITY.md) · [Troubleshooting](Docs/troubleshooting.md) · [Changelog](Docs/CHANGELOG.md)

## VISUAL APPLICATION  

![1](Images\overview.png)  
![2](Images\diagnose.png)  
![3](Images\cases.png)  
![4](Images\compare.png)  
![5](Images\settings.png)  
![6](Images\ai1.png)  
![7](Images\ai2.png)  

---

> [!IMPORTANT]
> Most of the project is build with AI, You can check the complete source code & Documentations. It is Tested and Safe To Use.

---

```
How i Got The IDEA ?  
        --> Legacy applications lead administrators to leave endpoint firewalls disabled <--

Domain: Endpoint hardening
Source: Reddit, r/sysadmin — New Firewall Recommendations, 19 October 2026.  
          "https://www.reddit.com/r/sysadmin/s/qYLA8XpK43"

Problem: An administrator says an accounting application appears to require a disabled Windows firewall, while its network-policy documentation is inadequate.  
“i tried to make incoming/outgoing policies, but they don't seems to have updated info on that” reddit.com

MY SOLUTION: A troubleshooting assistant correlating application activity with blocked connections and proposing narrow, reviewable rules with a validation plan.
```

Made By ViRuS. [GitHub](https://github.com/The-Real-Virus) · [LinkedIn](https://www.linkedin.com/in/syed-muhammad-shah)  
