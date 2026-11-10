# Contract module organization

Status: implementation decision within approved A00.

Consolidate the small core record definitions in contracts/models.py, sharing bounded primitives
and enums in base.py and enums.py. Keep desktop_job.py separate and Qt-free; keep AI contracts
in ai/contracts.py. This avoids circular schema dependencies while preserving the source
blueprint's ownership and validation boundaries. Collectors, parsers, services, analysis,
proposals, reports, GUI and AI remain separate layers. Schema export and negative tests cover
the public models directly; this decision changes no diagnostic behavior or support claim.
