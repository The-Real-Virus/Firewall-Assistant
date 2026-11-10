"""Shared-schema intent entry and plain, explicitly local case projections."""

from pathlib import Path

from PySide6.QtCore import QSortFilterProxyModel, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from wfdiag.contracts.models import Analysis, Finding, Intent
from wfdiag.gui.explanations import case_explanation, proposal_explanation
from wfdiag.gui.read_models import (
    EvidenceModel,
    EvidenceProxy,
    FindingsModel,
    PolicyModel,
    PolicyProxy,
    intended_flow,
)
from wfdiag.storage.analysis_index import AnalysisIndex


def text_label(text: str = "") -> QLabel:
    result = QLabel(text)
    result.setTextFormat(Qt.TextFormat.PlainText)
    result.setWordWrap(True)
    result.setTextInteractionFlags(
        Qt.TextInteractionFlag.TextSelectableByMouse
        | Qt.TextInteractionFlag.TextSelectableByKeyboard
    )
    return result


class IntentForm(QWidget):
    changed = Signal()

    def __init__(self) -> None:
        super().__init__()
        body = QVBoxLayout(self)
        self.enabled = QCheckBox("Focus on one application's connection (optional)")
        body.addWidget(self.enabled)
        self.fields = QWidget()
        form = QFormLayout(self.fields)
        form.setSpacing(12)
        self.application = QLineEdit()
        self.application.setPlaceholderText(
            "Choose the .exe of the application that cannot connect"
        )
        browse = QPushButton("Browse application")
        browse.clicked.connect(self.browse)
        form.addRow("&Application", self.application)
        form.addRow(browse)
        self.confirmed = QCheckBox("I verified this is the program whose connection is failing")
        form.addRow(self.confirmed)
        self.direction = QComboBox()
        self.direction.addItems(
            [
                "App connects to a website or server (outbound)",
                "Other computers connect to this app (inbound)",
            ]
        )
        form.addRow("&Direction", self.direction)
        self.connection_help = text_label(
            "For web browsing, choose outbound. The destination must be the actual website/server address; a DNS server is not automatically that destination. If you do not know these details, turn off application focus and use general review."
        )
        form.addRow(self.connection_help)
        self.port = QLineEdit()
        self.port.setPlaceholderText("Expected remote service port")
        form.addRow("Service &port", self.port)
        self.profile = QComboBox()
        self.profile.addItems(["Choose one profile", "Domain", "Private", "Public"])
        form.addRow("&Profile", self.profile)
        self.peer = QLineEdit()
        self.peer.setPlaceholderText(
            "Actual server/client IP address or approved CIDR; do not guess"
        )
        form.addRow("Expected &peer", self.peer)
        self.purpose = QLineEdit()
        self.purpose.setMaxLength(500)
        form.addRow("Connection p&urpose", self.purpose)
        body.addWidget(self.fields)
        self.fields.setEnabled(False)
        self.fields.hide()
        self.enabled.toggled.connect(self.fields.setEnabled)
        self.enabled.toggled.connect(self.fields.setVisible)
        self.enabled.toggled.connect(self.changed)
        self.confirmed.toggled.connect(self.changed)
        for edit in (self.application, self.port, self.peer, self.purpose):
            edit.textChanged.connect(self.changed)
        self.profile.currentIndexChanged.connect(self.changed)
        self.direction.currentIndexChanged.connect(self.direction_changed)

    def browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select verified application", "", "Programs (*.exe)"
        )
        if path:
            self.application.setText(path)
            self.confirmed.setChecked(False)

    def direction_changed(self) -> None:
        self.port.setPlaceholderText(
            "Expected local service port"
            if self.direction.currentIndex()
            else "Expected remote service port"
        )
        self.changed.emit()

    def value(self) -> Intent | None:
        if not self.enabled.isChecked():
            return None
        return intended_flow(
            application=self.application.text(),
            confirmed=self.confirmed.isChecked(),
            inbound=bool(self.direction.currentIndex()),
            profile=self.profile.currentText(),
            peers=self.peer.text(),
            port=self.port.text(),
            purpose=self.purpose.text(),
        )


class CaseView(QWidget):
    requestPermission = Signal()
    requestPage = Signal(int)
    exportShare = Signal()
    exportFull = Signal()
    exportProposal = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.analysis: Analysis | None = None
        self.result_index: AnalysisIndex | None = None
        self.path: Path | None = None
        self.synthetic = False
        self.stale = False
        self.busy = False
        self.page_index = 0
        self.policy_page_index = 0
        self.application_aliases: dict[str, str] = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 24)
        layout.setSpacing(16)
        self.title = text_label("Case workspace")
        self.title.setObjectName("title")
        layout.addWidget(self.title)
        self.explanation = text_label(
            "Open a collected case or training example to see its explanation."
        )
        self.explanation.setObjectName("badge")
        layout.addWidget(self.explanation)
        self.permission_button = QPushButton("Ask Windows for permission and collect again")
        self.permission_button.clicked.connect(self.requestPermission)
        self.permission_button.hide()
        layout.addWidget(self.permission_button)
        technical = QCheckBox("Show technical collection details")
        layout.addWidget(technical)
        self.status = text_label("Choose a validated case or open the synthetic example.")
        self.status.setObjectName("badge")
        layout.addWidget(self.status)
        self.metadata = text_label()
        layout.addWidget(self.metadata)
        self.status.hide()
        self.metadata.hide()
        technical.toggled.connect(self.status.setVisible)
        technical.toggled.connect(self.metadata.setVisible)
        self.tabs = QTabWidget()
        self.tabs.setAccessibleName("Case workspace")
        layout.addWidget(self.tabs, 1)
        findings = QWidget()
        listing = QVBoxLayout(findings)
        listing.setContentsMargins(20, 20, 20, 20)
        self.search = QLineEdit()
        self.search.setMaxLength(200)
        self.search.setPlaceholderText("Search loaded findings page only (maximum500 rows)")
        self.search.setAccessibleName("Search loaded finding summaries only")
        listing.addWidget(self.search)
        paging = QHBoxLayout()
        self.previous_page = QPushButton("Previous page")
        self.next_page = QPushButton("Next page")
        self.page_label = text_label("No findings loaded")
        self.previous_page.clicked.connect(lambda: self.load_page(self.page_index - 1))
        self.next_page.clicked.connect(lambda: self.load_page(self.page_index + 1))
        paging.addWidget(self.previous_page)
        paging.addWidget(self.page_label, 1)
        paging.addWidget(self.next_page)
        listing.addLayout(paging)
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.table = QTableView()
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setFilterKeyColumn(-1)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.search_timer = QTimer(self)
        self.search_timer.setSingleShot(True)
        self.search_timer.setInterval(200)
        self.search.textChanged.connect(lambda: self.search_timer.start())
        self.search_timer.timeout.connect(
            lambda: self.proxy.setFilterFixedString(self.search.text())
        )
        self.table.setModel(self.proxy)
        self.table.setAccessibleName("Engine findings")
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(60)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setWordWrap(True)
        self.table.setAlternatingRowColors(True)
        self.table.setMinimumHeight(116)
        self.table.selectionModel().currentChanged.connect(self.selection_changed)
        self.splitter.addWidget(self.table)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setAccessibleName("Finding summary and uncertainty")
        self.splitter.addWidget(self.detail)
        self.splitter.setSizes([500, 400])
        listing.addWidget(self.splitter, 1)
        self.tabs.addTab(findings, "Findings")
        evidence = QWidget()
        evidence.setObjectName("page")
        evidence_layout = QVBoxLayout(evidence)
        self.reveal = QCheckBox("Reveal sensitive local evidence on this page")
        evidence_layout.addWidget(self.reveal)
        evidence_layout.addWidget(
            text_label(
                "Local details can contain paths, addresses and rule identities. Imported text is plain. Search and sorting cover this loaded page only; hidden fields are not searched or sorted. Changing page or finding hides details again."
            )
        )
        self.evidence_search = QLineEdit()
        self.evidence_search.setMaxLength(200)
        self.evidence_search.setPlaceholderText("Search this loaded evidence page only")
        self.evidence_search.setAccessibleName(
            "Search loaded evidence page; hidden fields excluded"
        )
        evidence_layout.addWidget(self.evidence_search)
        self.evidence_page_label = text_label("No loaded evidence page")
        evidence_layout.addWidget(self.evidence_page_label)
        self.evidence_table = QTableView()
        self.evidence_proxy = EvidenceProxy(self)
        self.evidence_proxy.setFilterKeyColumn(-1)
        self.evidence_proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.evidence_table.setModel(self.evidence_proxy)
        self.evidence_table.selectionModel().currentChanged.connect(self.evidence_selection_changed)
        self.evidence_table.setAccessibleName("Loaded normalized Security observations; maximum500")
        self.evidence_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.evidence_table.setSortingEnabled(True)
        self.evidence_table.sortByColumn(-1, Qt.SortOrder.AscendingOrder)
        self.evidence_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        # A small viewport does not need to inspect every record to size its columns.
        # Retain all500 searchable/sortable rows; bound only the width sampling work.
        self.evidence_table.horizontalHeader().setResizeContentsPrecision(16)
        self.evidence_table.setMinimumHeight(110)
        self.evidence_table.setMaximumHeight(200)
        evidence_layout.addWidget(self.evidence_table)
        evidence_paging = QHBoxLayout()
        previous_evidence = QPushButton("Previous evidence page")
        next_evidence = QPushButton("Next evidence page")
        previous_evidence.clicked.connect(lambda: self.load_page(self.page_index - 1))
        next_evidence.clicked.connect(lambda: self.load_page(self.page_index + 1))
        evidence_paging.addWidget(previous_evidence)
        evidence_paging.addWidget(next_evidence)
        evidence_layout.addLayout(evidence_paging)
        self.evidence_timer = QTimer(self)
        self.evidence_timer.setSingleShot(True)
        self.evidence_timer.setInterval(200)
        self.evidence_search.textChanged.connect(lambda: self.evidence_timer.start())
        self.evidence_timer.timeout.connect(
            lambda: self.evidence_proxy.setFilterFixedString(self.evidence_search.text())
        )
        self.evidence = QPlainTextEdit()
        self.evidence.setReadOnly(True)
        self.evidence.setMinimumHeight(160)
        self.evidence.setAccessibleName("Selected local evidence")
        evidence_layout.addWidget(self.evidence)
        evidence_layout.addWidget(text_label("Policy candidates and source provenance"))
        self.policy_scope = QComboBox()
        self.policy_scope.addItems(
            ("All rules on this page", "Selected finding candidates on this page")
        )
        self.policy_scope.setAccessibleName("Policy rule scope on the loaded page")
        self.policy_scope.currentIndexChanged.connect(self.update_policy_candidates)
        evidence_layout.addWidget(self.policy_scope)
        self.policy_search = QLineEdit()
        self.policy_search.setMaxLength(200)
        self.policy_search.setPlaceholderText(
            "Search this policy page only; hidden identities excluded"
        )
        self.policy_search.setAccessibleName("Search loaded policy page only")
        evidence_layout.addWidget(self.policy_search)
        self.policy_proxy = PolicyProxy(self)
        self.policy_proxy.setFilterKeyColumn(-1)
        self.policy_proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.policy_timer = QTimer(self)
        self.policy_timer.setSingleShot(True)
        self.policy_timer.setInterval(200)
        self.policy_search.textChanged.connect(lambda: self.policy_timer.start())
        self.policy_timer.timeout.connect(
            lambda: self.policy_proxy.setFilterFixedString(self.policy_search.text())
        )
        self.policy_table = QTableView()
        self.policy_table.setModel(self.policy_proxy)
        self.policy_table.setAccessibleName(
            "Loaded policy rules; maximum500; candidates are not confirmed causes"
        )
        self.policy_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.policy_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.policy_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.policy_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.policy_table.horizontalHeader().setResizeContentsPrecision(16)
        self.policy_table.setMinimumHeight(110)
        self.policy_table.setMaximumHeight(200)
        self.policy_table.selectionModel().currentChanged.connect(self.show_rule)
        evidence_layout.addWidget(self.policy_table)
        policy_paging = QHBoxLayout()
        self.previous_policy = QPushButton("Previous policy page")
        self.next_policy = QPushButton("Next policy page")
        self.policy_page_label = text_label("Policy snapshot not loaded")
        self.previous_policy.clicked.connect(
            lambda: self.load_policy_page(self.policy_page_index - 1)
        )
        self.next_policy.clicked.connect(lambda: self.load_policy_page(self.policy_page_index + 1))
        policy_paging.addWidget(self.previous_policy)
        policy_paging.addWidget(self.policy_page_label, 1)
        policy_paging.addWidget(self.next_policy)
        evidence_layout.addLayout(policy_paging)
        self.policy_detail = QPlainTextEdit()
        self.policy_detail.setReadOnly(True)
        self.policy_detail.setMinimumHeight(130)
        self.policy_detail.setMaximumHeight(200)
        self.policy_detail.setAccessibleName("Selected local rule conditions and provenance")
        evidence_layout.addWidget(self.policy_detail)
        self.source_detail = QPlainTextEdit()
        self.source_detail.setReadOnly(True)
        self.source_detail.setMinimumHeight(110)
        self.source_detail.setMaximumHeight(180)
        self.source_detail.setAccessibleName("Case source completeness and provenance")
        evidence_layout.addWidget(self.source_detail)
        self.reveal.toggled.connect(self.reveal_changed)
        self.evidence_scroll = QScrollArea()
        self.evidence_scroll.setWidgetResizable(True)
        self.evidence_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.evidence_scroll.setWidget(evidence)
        self.tabs.addTab(self.evidence_scroll, "Evidence")
        proposal = QWidget()
        proposal_layout = QVBoxLayout(proposal)
        self.proposal = QPlainTextEdit()
        self.proposal.setReadOnly(True)
        self.proposal.setAccessibleName("Proposal eligibility and refusal reasons")
        proposal_layout.addWidget(self.proposal)
        self.proposal_button = QPushButton("Export proposal JSON")
        self.proposal_button.clicked.connect(self.exportProposal)
        proposal_layout.addWidget(self.proposal_button)
        self.proposal_button.setEnabled(False)
        self.tabs.addTab(proposal, "Proposal")
        export = QWidget()
        export_layout = QVBoxLayout(export)
        export_layout.addWidget(
            text_label(
                "Share reports use the shared engine's allowlist redaction. Full reports contain sensitive local details. Review any report before sharing."
            )
        )
        self.share_button = QPushButton("Export share report")
        self.full_button = QPushButton("Export local full report")
        self.share_button.clicked.connect(self.exportShare)
        self.full_button.clicked.connect(self.exportFull)
        export_layout.addWidget(self.share_button)
        export_layout.addWidget(self.full_button)
        export_layout.addStretch()
        self.tabs.addTab(export, "Export")
        self.share_button.setEnabled(False)
        self.full_button.setEnabled(False)

    def bind(
        self, result: Analysis | AnalysisIndex, path: Path | None, *, synthetic: bool = False
    ) -> None:
        old_index = self.result_index
        self.result_index = result if isinstance(result, AnalysisIndex) else None
        analysis = result.first_page if isinstance(result, AnalysisIndex) else result
        self.analysis, self.path, self.synthetic = analysis, path, synthetic
        if old_index is not None and old_index is not self.result_index:
            old_index.close()
        self.stale = False
        self.reveal.setChecked(False)
        self.title.setText("Example case" if synthetic else "Local case")
        self.search_timer.stop()
        self.evidence_timer.stop()
        self.search.clear()
        self.evidence_search.clear()
        self.policy_timer.stop()
        self.policy_search.clear()
        self.application_aliases.clear()
        self.display_page(analysis, 0)
        self.load_policy_page(0)
        source_states = " · ".join(f"{s.source}: {s.state.value}" for s in analysis.sources)
        self.metadata.setText(
            f"Engine {analysis.engine_version} · Analyzed {analysis.analyzed_at_utc.isoformat()}\n"
            f"Intent: {'specific TCP flow' if analysis.intent else 'general analysis; no proposals'}\n{source_states}"
        )
        self.refresh_status()
        self.share_button.setEnabled(path is not None or synthetic)
        self.full_button.setEnabled(path is not None or synthetic)
        self.show_selected()

    def load_page(self, index: int) -> None:
        if self.analysis is None:
            return
        last_page = max(0, (self.total_findings - 1) // 500)
        index = min(max(0, index), last_page)
        if self.result_index is not None:
            if not self.busy:
                self.requestPage.emit(index)
            return
        self.display_page(self.analysis, index)

    @property
    def total_findings(self) -> int:
        return (
            self.result_index.count
            if self.result_index is not None
            else len(self.analysis.findings)
            if self.analysis is not None
            else 0
        )

    def display_page(self, analysis: Analysis, index: int) -> None:
        self.analysis = analysis
        self.page_index = index
        self.reveal.setChecked(False)
        previous = self.proxy.sourceModel()
        self.proxy.setSourceModel(
            FindingsModel(
                analysis,
                self.proxy,
                page=0 if self.result_index is not None else self.page_index,
                aliases=self.application_aliases,
            )
        )
        if previous is not None:
            previous.deleteLater()
        self.proxy.setFilterFixedString(self.search.text())
        offset = self.page_index * 500
        page = (
            analysis.findings
            if self.result_index is not None
            else analysis.findings[offset : offset + 500]
        )
        old_evidence = self.evidence_proxy.sourceModel()
        self.evidence_proxy.setSourceModel(EvidenceModel(page, self.evidence_proxy))
        if old_evidence is not None:
            old_evidence.deleteLater()
        self.evidence_proxy.setFilterFixedString(self.evidence_search.text())
        total = self.total_findings
        last_page = max(0, (total - 1) // 500)
        self.page_label.setText(
            f"Findings {offset + 1 if total else 0}–{offset + len(page)} of {total}\nSearch covers this loaded page only"
        )
        self.evidence_page_label.setText(
            f"Normalized observations from findings page {self.page_index + 1}; maximum500. Search is not exhaustive across the case. Source status and provenance remain in the case/selected record."
        )
        self.previous_page.setEnabled(self.page_index > 0)
        self.next_page.setEnabled(self.page_index < last_page)
        if self.proxy.rowCount():
            self.table.selectRow(0)
        self.show_selected()

    def selection_changed(self) -> None:
        self.reveal.setChecked(False)
        self.show_selected()

    def evidence_selection_changed(self) -> None:
        source = self.evidence_proxy.sourceModel()
        index = self.evidence_proxy.mapToSource(self.evidence_table.currentIndex())
        findings = self.proxy.sourceModel()
        if (
            not isinstance(source, EvidenceModel)
            or not isinstance(findings, FindingsModel)
            or not index.isValid()
        ):
            return
        source_row = source.finding_rows[index.row()]
        target = self.proxy.mapFromSource(findings.index(source_row, 0))
        if not target.isValid():
            self.search.clear()
            self.proxy.setFilterFixedString("")
            target = self.proxy.mapFromSource(findings.index(source_row, 0))
        if target.isValid() and target.row() != self.table.currentIndex().row():
            self.table.selectRow(target.row())

    def reveal_changed(self) -> None:
        source = self.evidence_proxy.sourceModel()
        if isinstance(source, EvidenceModel) and source.revealed != self.reveal.isChecked():
            source.reveal(self.reveal.isChecked())
            self.evidence_proxy.invalidate()
        policy = self.policy_proxy.sourceModel()
        if isinstance(policy, PolicyModel) and policy.revealed != self.reveal.isChecked():
            policy.reveal(self.reveal.isChecked())
            self.policy_proxy.invalidate()
        self.show_rule()
        if self.analysis is not None:
            if self.reveal.isChecked():
                sources = "\n\n".join(s.model_dump_json(indent=2) for s in self.analysis.sources)
                self.source_detail.setPlainText(
                    sources[:100000] + ("\n[Display capped]" if len(sources) > 100000 else "")
                )
            else:
                self.source_detail.setPlainText(
                    "Source status\n"
                    + "\n".join(f"{s.source}: {s.state.value}" for s in self.analysis.sources)
                    + "\nReveal local details for timestamps, counts, limitations and source references."
                )
        self.show_selected()

    def load_policy_page(self, index: int) -> None:
        if self.analysis is None:
            return
        self.reveal.setChecked(False)
        total = len(self.analysis.policy_rules or ())
        last = max(0, (total - 1) // 500)
        self.policy_page_index = min(max(0, index), last)
        old = self.policy_proxy.sourceModel()
        source = PolicyModel(self.analysis, self.policy_page_index, self.policy_proxy)
        self.policy_proxy.setSourceModel(source)
        if old is not None:
            old.deleteLater()
        self.policy_proxy.setFilterFixedString(self.policy_search.text())
        self.previous_policy.setEnabled(self.policy_page_index > 0)
        self.next_policy.setEnabled(self.policy_page_index < last)
        self.policy_page_label.setText(
            "Policy snapshot unavailable; do not infer no rules."
            if not source.available
            else f"Rules {source.offset + 1 if total else 0}–{source.offset + len(source.rules)} of {total}. Search/filter covers this page only. Candidates are not confirmed causes."
        )
        self.update_policy_candidates()
        if self.policy_proxy.rowCount():
            self.policy_table.selectRow(0)
        self.reveal_changed()

    def update_policy_candidates(self) -> None:
        # This callback can fire during setup before the model is constructed.
        if not hasattr(self, "policy_proxy"):
            return
        finding = self.selected()
        candidates = (
            (finding.candidate_rules if finding is not None else ())
            if self.policy_scope.currentIndex()
            else None
        )
        self.policy_proxy.set_candidates(candidates)
        self.show_rule()

    def show_rule(self) -> None:
        source = self.policy_proxy.sourceModel()
        index = self.policy_proxy.mapToSource(self.policy_table.currentIndex())
        rule = (
            source.rule(index.row())
            if isinstance(source, PolicyModel) and index.isValid()
            else None
        )
        if rule is None:
            self.policy_detail.setPlainText(
                "Select a rule on this loaded page. No visible candidate is not evidence that the full case has none."
            )
        elif not self.reveal.isChecked():
            self.policy_detail.setPlainText(
                "Rule identity, conditions and provenance are hidden until Reveal. Policy candidates are not confirmed causes."
            )
        else:
            text = rule.model_dump_json(indent=2)
            self.policy_detail.setPlainText(
                text[:100000]
                + (
                    "\n[Display capped; use a local full report for the complete rule.]"
                    if len(text) > 100000
                    else ""
                )
            )

    def refresh_status(self) -> None:
        if self.analysis is None:
            return
        self.explanation.setText(case_explanation(self.analysis, self.synthetic))
        parts = (
            ["SYNTHETIC EXAMPLE · Not collected from this computer"]
            if self.synthetic
            else ["LOCAL CASE"]
        )
        parts.append(
            f"Evidence {self.analysis.completeness.value}; completion is not a security verdict"
        )
        if self.stale:
            parts.append(
                "Intent changed · Reanalyze before requesting a proposal; reopen the original evidence case"
            )
        if self.analysis.completeness.value == "incomplete":
            parts.append("Review source gaps and obtain approved missing evidence")
        self.status.setText("\n".join(parts))
        self.show_selected()

    def selected(self) -> Finding | None:
        source = self.proxy.sourceModel()
        if isinstance(source, FindingsModel):
            return source.finding(self.proxy.mapToSource(self.table.currentIndex()).row())
        return None

    def show_selected(self) -> None:
        self.update_policy_candidates()
        finding = self.selected()
        if finding is None or self.analysis is None:
            self.detail.setPlainText(
                "Select a finding. No selection is not proof of a healthy host."
            )
            self.evidence.clear()
            self.proposal.clear()
            self.proposal_button.setEnabled(False)
            return
        self.detail.setPlainText(
            f"Observation\n{finding.category.value.replace('_', ' ').capitalize()}\n\n"
            f"Evidence grade: {finding.evidence_grade.value}\nRelevance: {finding.relevance.value}\n\n"
            f"Limitations\n{len(finding.limitations)} recorded; {len(finding.alternative_explanations)} alternative explanations. Reveal local evidence to review their text.\n\n"
            "Next steps\n"
            + "\n".join(step.value.replace("_", " ").capitalize() for step in finding.next_steps)
        )
        if finding.category.value == "EVIDENCE_GAP":
            self.detail.setPlainText(
                case_explanation(self.analysis, self.synthetic)
                + "\n\nWhat this means\nThe missing evidence prevents a reliable conclusion. It does not establish that an application is blocked, allowed or repaired.\n\nNext step\nReview the source explanation above. Use the Windows permission button if log access was denied; otherwise obtain the missing evidence and analyze a new case."
            )
        if self.reveal.isChecked():
            local = finding.model_dump_json(indent=2)
            self.evidence.setPlainText(
                local[:100000]
                + (
                    "\n[Display capped; use a local full report for the complete record.]"
                    if len(local) > 100000
                    else ""
                )
            )
        else:
            self.evidence.setPlainText(
                f"{len(finding.evidence_refs)} evidence references; {len(finding.candidate_rules)} policy candidates. Sensitive local details are hidden."
            )
        self.proposal.setPlainText(
            proposal_explanation(
                self.analysis, finding.proposal_eligible, self.synthetic, self.stale
            )
            + "\n\n"
            + "The shared engine rechecks eligibility on export. Proposals are nonexecuting JSON.\n\n"
            f"Engine eligibility: {'eligible for review' if finding.proposal_eligible else 'withheld'}\n"
            f"Refusals: {len(finding.refusal_codes)}. Reveal local evidence for exact codes.\n"
            + ("Intent changed: reanalysis required.\n" if self.stale else "")
            + ("Synthetic training data; no operational authorization.\n" if self.synthetic else "")
        )
        self.proposal_button.setEnabled(
            self.path is not None
            and not self.stale
            and not self.synthetic
            and not self.busy
            and finding.proposal_eligible
        )
