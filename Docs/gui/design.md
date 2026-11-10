# Desktop design baseline

U02 layout and both themes were explicitly approved on2 November2026 against actual Qt captures.
The source's original synthetic composition is a design reference, not an application screenshot.
Implemented source follows
Qt Widgets/Fusion, native title controls, original local SVG/.ico resources, a narrow navigation
rail, readable split findings/detail views and resizable/scrolling minimum 1000x700 layout.
Default about 1280x840 where the screen permits; collapse/reflow at smaller work areas.

Navigation: Overview, Diagnose, Cases, Compare, Settings; separate secondary AI Assistant.
Case tabs: Findings, Evidence, Proposal, Export. Overview offers Start diagnosis, Open case
folder and clearly labelled Open example. No startup collection, AI setup promotion or invented
health statistics. General analysis without intent remains available. Collection is deliberate
lookback, not live capture/countdown; the target is never launched or probed.

Central token baseline from source: light background #F4F7FB, surface #FFFFFF, raised #EDF2F8,
text #172033/#475569, border #CBD5E1, accent/focus #1D4ED8, button text #FFFFFF. Dark background
#0B1220, surface #111C2E, raised #18263B, text #E8EEF8/#A7B7CE, border #34445E, accent #93C5FD,
focus #BFDBFE, button text #0B1220. Original border tokens remain decorative. On5 November a
measured control-outline fix added separate Light#7A879B/Dark#6B7F9E boundaries, preserving the
approved palette/layout direction. Both exceed3:1 on selected adjacent surfaces; primary-button
and navigation focus rules are explicit. See contrast.md for source-only measurements and limits.
High contrast uses OS palette. System theme
default with Light/Dark/System override. Segoe UI fallback, 14 px base/12 secondary/26 title/18
section; 4/8/12/16/24/32 spacing, controls >=36 px and primary >=40, radii 8/12, rows >=36.

Use keyboard labels, visible focus, plain text/no URL activation, selectable local evidence,
typed table sorting, QAbstractTableModel/QTableView with 500-record default pages and declared
search scope. Heavy I/O/parsing/hashing/filtering/reporting stays off GUI thread. Debounce about
200 ms; <=10 visible progress refreshes/s. One active job/window and one instance/user session.
History opt-in, private, max20; clearing it never deletes a case. Revalidate reopened cases.

Statuses distinguish idle/validating/running/incomplete/no relevant event/unsupported/denied/
cancel requested/cancelled/failed. Exit5 stays incomplete. No fabricated percentages, immediate
cancellation claims, stale result reuse or completion after protocol/process/output disagreement.
Intent edits invalidate proposals; old job signals cannot update another case. Close offers
Keep running in this window or Cancel and close; no hidden tray process or auto-resumed collection.

Proposal action is Export proposal JSON only. Share is default export through engine redaction;
local full report needs disclosure confirmation. Imported HTML is never automatically opened.
AI defaults disabled with no provider/model/key/history; opening/configuring never sends.
Each send/test previews exact outgoing content and destination; answers remain labelled plain
text beside immutable engine facts. No saved key is erased merely by disabling unless explicitly
chosen. Credentials, retention and potential charges are explained without billing guarantees.

Working design checkpoint: actual synthetic screenshots of Overview, validation, findings,
incomplete, refusal, eligible proposal, share export, comparison, recovery and AI destination
where feasible; both themes plus minimum-size/high-scaling views. Owner approves layout/themes
before broad polishing. Native Narrator, keyboard, scaling/high contrast and responsiveness
remain separate measured acceptance; a polished screenshot cannot pass them.
