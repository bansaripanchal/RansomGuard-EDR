import os
from PySide6.QtCore import QAbstractTableModel, Qt, QModelIndex
from PySide6.QtGui import QColor

def format_file_size(size):
    """
    Standardized, authentic file size formatter across RansomGuard.
    Strict requirement: The main UI / tables must show file sizes in MB or GB, NOT B or KB.
    Exact bytes remain available via tooltips or inspection details.
    Examples:
        0.00 MB (0-byte file)
        0.01 MB (< 10 KB)
        0.25 MB
        1.5 MB
        25.4 MB
        1.2 GB
    """
    if size is None or size == -2:
        return "Unavailable"
    elif size == -1:
        return "Deleted before capture"
    elif size < 0:
        return "Unavailable"
    elif size == 0:
        return "0.00 MB"
    elif size < 1024 * 1024 * 1024:
        mb = size / (1024 * 1024)
        if mb < 0.01:
            return "0.01 MB"
        elif mb < 10.0:
            # Show up to 2 decimals, strip trailing zero if clean (e.g. 1.5 MB instead of 1.50 MB)
            formatted = f"{mb:.2f}"
            if formatted.endswith("0"):
                formatted = formatted[:-1]
            return f"{formatted} MB"
        else:
            return f"{mb:.1f} MB"
    else:
        gb = size / (1024 * 1024 * 1024)
        return f"{gb:.1f} GB"

class LiveEventsTableModel(QAbstractTableModel):
    """
    Highly performant, in-memory table model for real-time filesystem logs.
    Enforces a strict rolling size limit to prevent memory bloat.
    Columns: Timestamp, Operation, Path, Description, Ext, File Size (No Process column).
    """
    def __init__(self, max_rows=1000):
        super(LiveEventsTableModel, self).__init__()
        self.headers = ["Timestamp", "Operation", "Path", "Description", "Ext", "File Size"]
        self.events = []
        self.max_rows = max_rows

    def rowCount(self, parent=QModelIndex()):
        return len(self.events)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self.events)):
            return None

        event = self.events[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                return event.get("timestamp", "")
            elif col == 1:
                return event.get("event_type", "")
            elif col == 2:
                return event.get("src_path", "")
            elif col == 3:
                ev_type = event.get("event_type", "")
                dest = event.get("dest_path", "")
                if ev_type == "RENAME" and dest:
                    return f"Renamed to: {os.path.basename(dest)}"
                elif ev_type == "CREATE":
                    return "New file created"
                elif ev_type == "MODIFY":
                    return "File contents modified"
                elif ev_type == "DELETE":
                    return "File deleted"
                return "Filesystem activity"
            elif col == 4:
                return event.get("extension", "")
            elif col == 5:
                return format_file_size(event.get("file_size"))
                
        # Text alignments
        if role == Qt.TextAlignmentRole:
            if col in (0, 1, 4, 5):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        # Tooltips for complete absolute paths and exact byte sizes
        if role == Qt.ToolTipRole:
            if col == 2:
                src = event.get("src_path", "")
                dest = event.get("dest_path", "")
                if dest and event.get("event_type") == "RENAME":
                    return f"Source: {src}\nDestination: {dest}"
                return src
            elif col == 3:
                return event.get("dest_path") or ""
            elif col == 5:
                size = event.get("file_size")
                if size is not None and size >= 0:
                    return f"Actual Size: {size:,} bytes"
                elif size == -1:
                    return "File removed from disk prior to size telemetry capture"
                return "Filesystem size telemetry unavailable"

        return None

    def append_events(self, new_events):
        """Appends a batch of events and trims old rows to max_rows."""
        if not new_events:
            return

        self.beginInsertRows(QModelIndex(), 0, len(new_events) - 1)
        # Prepend to display newest at the top
        self.events = new_events + self.events
        self.endInsertRows()

        # Prune if exceeding max size
        if len(self.events) > self.max_rows:
            self.beginRemoveRows(QModelIndex(), self.max_rows, len(self.events) - 1)
            self.events = self.events[:self.max_rows]
            self.endRemoveRows()

    def set_events(self, events):
        """Replaces events list directly."""
        self.beginResetModel()
        self.events = list(events)
        self.endResetModel()

    def clear(self):
        self.beginResetModel()
        self.events.clear()
        self.endResetModel()


class IncidentsTableModel(QAbstractTableModel):
    """
    Table model for threat incidents database listings in Threat Repository.
    SOC/EDR Columns:
    0: THREAT / INCIDENT
    1: SEVERITY
    2: RISK
    3: DETECTED
    4: SOURCE
    5: TARGET
    6: STATUS
    7: ACTION
    8: DISMISS
    """
    def __init__(self, incidents=None):
        super(IncidentsTableModel, self).__init__()
        self.headers = [
            "THREAT / INCIDENT",
            "SEVERITY",
            "RISK",
            "DETECTED",
            "SOURCE",
            "TARGET",
            "STATUS",
            "ACTION",
            "DISMISS"
        ]
        self.all_incidents = incidents or []
        self.incidents = list(self.all_incidents)
        self.search_text = ""

    def rowCount(self, parent=QModelIndex()):
        return len(self.incidents)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]
        if role == Qt.ToolTipRole and orientation == Qt.Horizontal:
            if section == 8:
                return "Dismiss threat from repository"
            elif section == 7:
                return "Click to inspect incident investigation details"
        return None

    def _format_detection_time(self, t_str):
        if not t_str:
            return "Not available"
        try:
            import datetime
            s = str(t_str).strip()
            if "T" in s:
                dt = datetime.datetime.fromisoformat(s)
            else:
                dt = datetime.datetime.strptime(s.split(".")[0], "%Y-%m-%d %H:%M:%S")
            return dt.strftime("%d %b %Y %H:%M")
        except Exception:
            return str(t_str)

    def _determine_source(self, inc):
        src = inc.get("detection_source")
        if src and str(src).strip() and str(src) != "None":
            return str(src)
        threat_name = inc.get("threat_name", "")
        if "(Existing File Scan)" in threat_name:
            return "Existing File Scan"
        if "(Scan Center)" in threat_name:
            return "Scan Center"
        if inc.get("full_path") and not inc.get("affected_folder"):
            return "Scan Center"
        return "Live Protection"

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self.incidents)):
            return None

        inc = self.incidents[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                name = inc.get("threat_name", "Security Threat")
                for suffix in [" (Existing File Scan)", " (Scan Center)"]:
                    if name.endswith(suffix):
                        name = name[:-len(suffix)]
                return name
            elif col == 1:
                return inc.get("severity", "LOW").upper()
            elif col == 2:
                return f"{inc.get('risk_score', 0)}/100"
            elif col == 3:
                return self._format_detection_time(inc.get("detection_time"))
            elif col == 4:
                return self._determine_source(inc)
            elif col == 5:
                target = inc.get("affected_file")
                if not target:
                    full = inc.get("full_path") or inc.get("affected_folder")
                    if full:
                        target = os.path.basename(full)
                return target or "Not available"
            elif col == 6:
                return inc.get("status", "ACTIVE").upper()
            elif col == 7:
                return "Investigate →"
            elif col == 8:
                return "×"

        if role == Qt.ForegroundRole:
            if col == 1:  # SEVERITY
                sev = str(inc.get("severity", "LOW")).upper()
                if sev == "CRITICAL":
                    return QColor("#EF4444")
                elif sev == "HIGH":
                    return QColor("#F97316")
                elif sev == "MEDIUM":
                    return QColor("#F59E0B")
                else:
                    return QColor("#3B82F6")
            elif col == 6:  # STATUS
                st = str(inc.get("status", "ACTIVE")).upper()
                return QColor("#22C55E") if st == "RESOLVED" else QColor("#EF4444")
            elif col == 7:  # ACTION
                return QColor("#3B82F6")
            elif col == 8:  # DISMISS
                return QColor("#94A3B8")

        if role == Qt.TextAlignmentRole:
            if col in (1, 2, 3, 4, 6, 7, 8):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        # Tooltips for complete absolute paths & detection details
        if role == Qt.ToolTipRole:
            full_path = inc.get("full_path") or inc.get("affected_folder") or "Not available"
            reason = inc.get("detection_reason") or "Not available"
            sha256 = inc.get("sha256") or "Not available"
            if col in (0, 5):
                return f"Path: {full_path}\nSHA-256: {sha256}\nReason: {reason}"
            elif col == 3:
                return f"Detection Timestamp: {inc.get('detection_time', 'Not available')}"
            elif col == 7:
                return "Click to inspect full incident telemetry, detection rules, and activity timeline."
            elif col == 8:
                return "Dismiss threat from repository"
            return str(full_path)

        return None

    def set_incidents(self, incidents):
        """Reloads the model data and re-applies the active search filter."""
        self.all_incidents = incidents or []
        self._apply_search_filter()

    def set_search_query(self, query: str):
        """Filters incidents matching search query in name, file, path, or SHA-256."""
        self.search_text = (query or "").strip().lower()
        self._apply_search_filter()

    def _apply_search_filter(self):
        self.beginResetModel()
        if not self.search_text:
            self.incidents = list(self.all_incidents)
        else:
            q = self.search_text
            filtered = []
            for inc in self.all_incidents:
                t_name = str(inc.get("threat_name") or "").lower()
                f_name = str(inc.get("affected_file") or "").lower()
                f_path = str(inc.get("full_path") or "").lower()
                f_folder = str(inc.get("affected_folder") or "").lower()
                sha = str(inc.get("sha256") or "").lower()
                reason = str(inc.get("detection_reason") or "").lower()
                if q in t_name or q in f_name or q in f_path or q in f_folder or q in sha or q in reason:
                    filtered.append(inc)
            self.incidents = filtered
        self.endResetModel()

    def get_incident_at(self, row):
        if 0 <= row < len(self.incidents):
            return self.incidents[row]
        return None

    def dismiss_incident(self, inc_id: int):
        """Removes the specified incident from the visible table presentation immediately."""
        self.beginResetModel()
        self.all_incidents = [inc for inc in self.all_incidents if inc.get("id") != inc_id]
        self._apply_search_filter()
        self.endResetModel()


class IncidentActivityTableModel(QAbstractTableModel):
    """
    Dedicated table model for Incident Investigation Activity Timeline.
    Columns: TIME | ACTION | FILE / PATH | DESCRIPTION | SIZE
    """
    def __init__(self, events=None):
        super(IncidentActivityTableModel, self).__init__()
        self.headers = ["TIME", "ACTION", "FILE / PATH", "DESCRIPTION", "SIZE"]
        self.events = events or []

    def rowCount(self, parent=QModelIndex()):
        return len(self.events)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self.events)):
            return None

        ev = self.events[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                t = ev.get("timestamp", "")
                try:
                    import datetime
                    s = str(t).strip()
                    if "T" in s:
                        dt = datetime.datetime.fromisoformat(s)
                    else:
                        dt = datetime.datetime.strptime(s.split(".")[0], "%Y-%m-%d %H:%M:%S")
                    return dt.strftime("%H:%M:%S · %d %b")
                except Exception:
                    return str(t)
            elif col == 1:
                return ev.get("event_type", "ACTIVITY")
            elif col == 2:
                target = ev.get("dest_path") or ev.get("src_path") or ""
                return os.path.basename(target) if target else "Not available"
            elif col == 3:
                ev_type = ev.get("event_type", "")
                dest = ev.get("dest_path", "")
                if ev_type == "RENAME" and dest:
                    return f"Renamed to: {os.path.basename(dest)}"
                elif ev_type == "CREATE":
                    return "New file created"
                elif ev_type == "MODIFY":
                    return "File contents modified"
                elif ev_type == "DELETE":
                    return "File deleted"
                return ev.get("description") or "Filesystem activity"
            elif col == 4:
                return format_file_size(ev.get("file_size"))

        if role == Qt.ForegroundRole:
            if col == 1:
                ev_type = str(ev.get("event_type", "")).upper()
                if ev_type in ("CREATE",):
                    return QColor("#22C55E")
                elif ev_type in ("MODIFY",):
                    return QColor("#A855F7")
                elif ev_type in ("RENAME",):
                    return QColor("#F59E0B")
                elif ev_type in ("DELETE",):
                    return QColor("#EF4444")

        if role == Qt.TextAlignmentRole:
            if col in (0, 1, 4):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        if role == Qt.ToolTipRole:
            src = ev.get("src_path", "")
            dest = ev.get("dest_path", "")
            size = ev.get("file_size")
            size_str = f"Actual Size: {size:,} bytes" if size is not None and size >= 0 else "Size unavailable"
            if dest and ev.get("event_type") == "RENAME":
                return f"Source: {src}\nDestination: {dest}\n{size_str}"
            return f"Path: {src}\n{size_str}"

        return None

    def set_events(self, events):
        self.beginResetModel()
        self.events = list(events or [])
        self.endResetModel()

    def clear(self):
        self.beginResetModel()
        self.events.clear()
        self.endResetModel()



class ScanResultsTableModel(QAbstractTableModel):
    """
    Dedicated table model for Scan Center file and threat analysis results.
    Guarantees column values match their true headers:
    File Name, Verdict, Evidence / Reason, SHA-256, File Type, Size.
    """
    def __init__(self, records=None, parent=None):
        super(ScanResultsTableModel, self).__init__(parent)
        self.headers = ["File Name", "Verdict", "Evidence / Reason", "SHA-256", "File Type", "Size"]
        self.records = records or []

    def rowCount(self, parent=QModelIndex()):
        return len(self.records)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self.records)):
            return None

        rec = self.records[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                return rec.get("filename", "")
            elif col == 1:
                return rec.get("verdict", "")
            elif col == 2:
                return rec.get("reason", "")
            elif col == 3:
                sha = rec.get("sha256", "")
                if sha and sha not in ("Not available", "N/A") and len(sha) > 16:
                    return f"{sha[:10]}...{sha[-6:]}"
                return sha or "Not available"
            elif col == 4:
                return rec.get("file_type", "Unknown")
            elif col == 5:
                return format_file_size(rec.get("file_size"))

        # Text alignments
        if role == Qt.TextAlignmentRole:
            if col in (1, 4, 5):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        # Tooltips with full path, SHA-256 and exact byte size
        if role == Qt.ToolTipRole:
            if col == 0:
                return rec.get("file_path") or rec.get("filename", "")
            elif col == 2:
                return rec.get("reason", "")
            elif col == 3:
                return f"SHA-256: {rec.get('sha256', 'Not available')}"
            elif col == 5:
                size = rec.get("file_size")
                if size is not None and isinstance(size, (int, float)) and size >= 0:
                    return f"Actual Size: {int(size):,} bytes"
                return "Size unavailable"

        return None

    def set_records(self, records):
        self.beginResetModel()
        self.records = list(records)
        self.endResetModel()

    def append_records(self, new_records):
        if not new_records:
            return
        self.beginInsertRows(QModelIndex(), len(self.records), len(self.records) + len(new_records) - 1)
        self.records.extend(new_records)
        self.endInsertRows()

    def get_record_at(self, row):
        if 0 <= row < len(self.records):
            return self.records[row]
        return None

    def clear(self):
        self.beginResetModel()
        self.records.clear()
        self.endResetModel()


class HistoryTableModel(QAbstractTableModel):
    """
    Table model for administrative EDR audit history.
    """
    def __init__(self, logs=None):
        super(HistoryTableModel, self).__init__()
        self.headers = ["Timestamp", "Event Type", "Severity", "Description", "Target", "Action Taken"]
        self.logs = logs or []

    def rowCount(self, parent=QModelIndex()):
        return len(self.logs)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self.logs)):
            return None

        log = self.logs[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                return log.get("timestamp", "")
            elif col == 1:
                return log.get("event_type", "")
            elif col == 2:
                return log.get("severity", "")
            elif col == 3:
                return log.get("description", "")
            elif col == 4:
                return log.get("target", "") or "-"
            elif col == 5:
                return log.get("action_taken", "") or "-"

        if role == Qt.TextAlignmentRole:
            if col in (0, 1, 2):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        # Add ToolTip for long descriptions and targets
        if role == Qt.ToolTipRole:
            if col == 3:
                return log.get("description", "")
            elif col == 4:
                return log.get("target", "") or ""

        return None

    def set_logs(self, logs):
        self.beginResetModel()
        self.logs = logs
        self.endResetModel()

