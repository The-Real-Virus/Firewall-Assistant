"""Plain Qt projections. Diagnostic decisions stay in the shared engine."""

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    QSortFilterProxyModel,
    Qt,
)

from wfdiag.contracts.models import Analysis, Finding, Intent, Rule


def intended_flow(
    *,
    application: str,
    confirmed: bool,
    inbound: bool,
    profile: str,
    peers: str,
    port: str,
    purpose: str,
) -> Intent:
    import json

    if not port.isascii() or not port.isdecimal() or len(port) > 5:
        raise ValueError("Enter the independently approved service port")
    return Intent.model_validate_json(
        json.dumps(
            {
                "schema_version": "1.0",
                "application_path": application.strip(),
                "application_identity_confirmed": confirmed,
                "direction": "inbound" if inbound else "outbound",
                "protocol": "TCP",
                "profile": profile,
                "remote_addresses": [p.strip() for p in peers.split(",") if p.strip()],
                "local_port": int(port) if inbound else None,
                "remote_port": None if inbound else int(port),
                "purpose": purpose.strip(),
            }
        )
    )


class FindingsModel(QAbstractTableModel):
    headers = ("Finding", "Evidence grade", "Application", "Flow")

    def __init__(
        self,
        analysis: Analysis,
        parent: QObject | None = None,
        *,
        page: int = 0,
        aliases: dict[str, str] | None = None,
    ) -> None:
        super().__init__(parent)
        self.analysis = analysis
        self.offset = max(0, page) * 500
        self.count = max(0, min(500, len(analysis.findings) - self.offset))
        self.aliases = aliases if aliases is not None else {}
        self.rows: dict[int, tuple[str, str, str, str]] = {}

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex | None = None) -> int:
        return 0 if parent is not None and parent.isValid() else self.count

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex | None = None) -> int:
        return 0 if parent is not None and parent.isValid() else len(self.headers)

    def data(
        self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole
    ) -> object:
        if (
            not index.isValid()
            or not 0 <= index.row() < self.count
            or not 0 <= index.column() < len(self.headers)
        ):
            return None
        finding = self.analysis.findings[self.offset + index.row()]
        if role == Qt.ItemDataRole.UserRole:
            return finding
        if role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.AccessibleTextRole):
            return None
        if index.row() not in self.rows:
            event = finding.event
            identity = event.application_canonical if event is not None else None
            if identity is not None and identity not in self.aliases:
                self.aliases[identity] = f"Application {len(self.aliases) + 1}"
            protocol = (
                {6: "TCP", 17: "UDP", 1: "ICMPv4", 58: "ICMPv6"}.get(
                    event.protocol or 0, "Unknown protocol"
                )
                if event is not None
                else "Unknown protocol"
            )
            self.rows[index.row()] = (
                finding.category.value.replace("_", " ").capitalize(),
                finding.evidence_grade.value.capitalize(),
                self.aliases.get(identity or "", "Identity unresolved"),
                f"{protocol} · {event.direction.value if event is not None else 'unknown'}",
            )
            if event is None and finding.category.value in ("EVIDENCE_GAP", "NO_RELEVANT_EVENT"):
                self.rows[index.row()] = (
                    *self.rows[index.row()][:2],
                    "Not determined",
                    "Not evaluated"
                    if finding.category.value == "EVIDENCE_GAP"
                    else "No matching event",
                )
        return self.rows[index.row()][index.column()]

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> object:
        if (
            orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
            and 0 <= section < len(self.headers)
        ):
            return self.headers[section]
        return None

    def finding(self, row: int) -> Finding | None:
        return self.analysis.findings[self.offset + row] if 0 <= row < self.count else None


class EvidenceModel(QAbstractTableModel):
    headers = (
        "Observation",
        "UTC time",
        "Protocol",
        "Source address",
        "Source port",
        "Destination address",
        "Destination port",
    )

    def __init__(self, findings: tuple[Finding, ...], parent: QObject) -> None:
        super().__init__(parent)
        # Only the already-loaded findings page is projected. Never scan the entire case.
        self.finding_rows = tuple(
            index for index, finding in enumerate(findings[:500]) if finding.event is not None
        )
        self.events = tuple(
            event for finding in findings[:500] if (event := finding.event) is not None
        )
        self.revealed = False
        self.rows: dict[int, tuple[str, ...]] = {}

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex | None = None) -> int:
        return 0 if parent is not None and parent.isValid() else len(self.events)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex | None = None) -> int:
        return 0 if parent is not None and parent.isValid() else len(self.headers)

    def data(
        self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole
    ) -> object:
        if (
            not index.isValid()
            or not 0 <= index.row() < len(self.events)
            or not 0 <= index.column() < len(self.headers)
        ):
            return None
        if role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.AccessibleTextRole):
            return None
        column = index.column()
        if not self.revealed and column not in (0, 2):
            return "Hidden until Reveal"
        event = self.events[index.row()]
        protocol = {6: "TCP", 17: "UDP", 1: "ICMPv4", 58: "ICMPv6"}.get(
            event.protocol or 0, "Unknown"
        )
        if not self.revealed:
            return f"Security event {event.event_id}" if column == 0 else protocol
        if index.row() in self.rows:
            return self.rows[index.row()][column]
        values = (
            f"Security event {event.event_id}",
            event.timestamp_utc.isoformat(),
            protocol,
            event.source_address or "Unknown",
            str(event.source_port) if event.source_port is not None else "Unknown",
            event.destination_address or "Unknown",
            str(event.destination_port) if event.destination_port is not None else "Unknown",
        )
        self.rows[index.row()] = values
        return values[column]

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> object:
        return (
            self.headers[section]
            if orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
            and 0 <= section < len(self.headers)
            else None
        )

    def reveal(self, value: bool) -> None:
        if self.revealed == value:
            return
        self.revealed = value
        self.rows.clear()
        if self.events:
            self.dataChanged.emit(
                self.index(0, 0), self.index(len(self.events) - 1, len(self.headers) - 1)
            )

    def sort_key(self, row: int, column: int) -> tuple[int, ...]:
        from ipaddress import ip_address

        event = self.events[row]
        if column == 1:
            stamp = event.timestamp_utc
            return (
                stamp.year,
                stamp.month,
                stamp.day,
                stamp.hour,
                stamp.minute,
                stamp.second,
                stamp.microsecond,
            )
        if column in (3, 5):
            address = event.source_address if column == 3 else event.destination_address
            if address is None:
                return (0, 0)
            parsed = ip_address(address)
            return (parsed.version, int(parsed))
        number = (
            event.event_id
            if column == 0
            else event.protocol
            if column == 2
            else event.source_port
            if column == 4
            else event.destination_port
        )
        return (-1 if number is None else number,)


class EvidenceProxy(QSortFilterProxyModel):
    def lessThan(
        self, left: QModelIndex | QPersistentModelIndex, right: QModelIndex | QPersistentModelIndex
    ) -> bool:
        model = self.sourceModel()
        if isinstance(model, EvidenceModel):
            if not model.revealed and left.column() not in (0, 2):
                return left.row() < right.row()
            return model.sort_key(left.row(), left.column()) < model.sort_key(
                right.row(), right.column()
            )
        return super().lessThan(left, right)


class PolicyModel(QAbstractTableModel):
    """One bounded page; hidden identities cannot participate in search."""

    headers = ("Rule", "Action", "Direction", "Enabled", "Profiles", "Policy owner")

    def __init__(self, analysis: Analysis, page: int, parent: QObject) -> None:
        super().__init__(parent)
        self.available = analysis.policy_rules is not None
        self.total = len(analysis.policy_rules or ())
        self.offset = max(0, page) * 500
        self.rules = (analysis.policy_rules or ())[self.offset : self.offset + 500]
        self.revealed = False

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex | None = None) -> int:
        return 0 if parent is not None and parent.isValid() else len(self.rules)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex | None = None) -> int:
        return 0 if parent is not None and parent.isValid() else len(self.headers)

    def data(
        self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole
    ) -> object:
        if (
            not index.isValid()
            or not 0 <= index.row() < len(self.rules)
            or not 0 <= index.column() < len(self.headers)
        ):
            return None
        rule = self.rules[index.row()]
        if role == Qt.ItemDataRole.UserRole:
            return rule
        if role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.AccessibleTextRole):
            return None
        return (
            rule.rule_id if self.revealed else f"Rule {self.offset + index.row() + 1}",
            rule.action,
            rule.direction.value,
            "Unknown" if rule.enabled is None else "Yes" if rule.enabled else "No",
            ", ".join(p.value for p in rule.profiles) if rule.profiles is not None else "Unknown",
            rule.policy_source_type,
        )[index.column()]

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> object:
        return (
            self.headers[section]
            if orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
            and 0 <= section < len(self.headers)
            else None
        )

    def rule(self, row: int) -> Rule | None:
        return self.rules[row] if 0 <= row < len(self.rules) else None

    def reveal(self, value: bool) -> None:
        if self.revealed == value:
            return
        self.revealed = value
        if self.rules:
            self.dataChanged.emit(
                self.index(0, 0), self.index(len(self.rules) - 1, len(self.headers) - 1)
            )


class PolicyProxy(QSortFilterProxyModel):
    candidates: frozenset[str] | None = None

    def set_candidates(self, values: tuple[str, ...] | None) -> None:
        selected = frozenset(values) if values is not None else None
        if selected != self.candidates:
            self.candidates = selected
            self.invalidate()

    def filterAcceptsRow(self, row: int, parent: QModelIndex | QPersistentModelIndex) -> bool:
        source = self.sourceModel()
        if isinstance(source, PolicyModel) and self.candidates is not None:
            rule = source.rule(row)
            if rule is None or rule.rule_id not in self.candidates:
                return False
        return super().filterAcceptsRow(row, parent)
