# Contributing

For a bug report, include the app version, Windows edition and build, steps to reproduce, expected result, and actual result. Use an invented example or a sanitized summary. Keep raw firewall or Security logs, full cases, machine identifiers, and API keys out of the issue.

Use the rebuild guide to set up your development workspace and run the checks. Add coverage when your change alters diagnostic behavior. If the change affects an operator workflow, update the relevant documentation. Clearly identify checks that need real Windows hardware, administrator consent, or a live provider. [Development setup](REBUILD.md)

Changes to collectors, evidence handling, proposal eligibility, or AI actions should explain their effect on the read-only diagnostic boundary. [Architecture](architecture.md) · [Privacy](privacy.md)
