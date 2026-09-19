import os
import time
import getpass
import platform
import socket
import logging
from PySide6.QtCore import QThread, Signal
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from core.database.database import DatabaseManager
from core.database.incidents_repository import IncidentsRepository
from core.database.events_repository import EventsRepository

logger = logging.getLogger("RansomGuard.PDFReport")

class PDFReportGenerator(QThread):
    finished = Signal(str) # Path to the generated PDF
    error = Signal(str)

    def __init__(self, output_path, report_type="incidents", incident_id=None, db_manager=None):
        super(PDFReportGenerator, self).__init__()
        self.output_path = output_path
        self.report_type = report_type.lower()
        self.incident_id = incident_id
        self.db = db_manager or DatabaseManager()
        self.inc_repo = IncidentsRepository(self.db)
        self.events_repo = EventsRepository(self.db)

    def run(self):
        try:
            logger.info(f"Generating PDF report ({self.report_type}): {self.output_path}")
            
            # Diagnostic check and logging
            drives = self.db.get_active_drives()
            drives_str = ", ".join(drives) if drives else "None"
            
            # Setup Document
            doc = SimpleDocTemplate(
                self.output_path,
                pagesize=letter,
                rightMargin=36,
                leftMargin=36,
                topMargin=36,
                bottomMargin=36
            )
            
            styles = getSampleStyleSheet()
            
            title_style = ParagraphStyle(
                'ReportTitle',
                parent=styles['Heading1'],
                fontSize=18,
                leading=22,
                textColor=colors.HexColor('#0D1117'),
                spaceAfter=2
            )
            
            subtitle_style = ParagraphStyle(
                'ReportSubTitle',
                parent=styles['Heading2'],
                fontSize=12,
                leading=15,
                textColor=colors.HexColor('#3B82F6'),
                spaceAfter=6
            )

            section_heading_style = ParagraphStyle(
                'SectionHeading',
                parent=styles['Heading3'],
                fontSize=11,
                leading=14,
                textColor=colors.HexColor('#1E3A8A'),
                spaceBefore=8,
                spaceAfter=4
            )
            
            body_style = ParagraphStyle(
                'ReportBody',
                parent=styles['Normal'],
                fontSize=8.5,
                leading=11,
                textColor=colors.HexColor('#374151'),
                spaceAfter=3
            )
            
            meta_style = ParagraphStyle(
                'MetaText',
                parent=styles['Normal'],
                fontSize=8,
                leading=10,
                textColor=colors.HexColor('#6B7280')
            )

            table_header_style = ParagraphStyle(
                'TableHeader',
                parent=styles['Normal'],
                fontSize=8,
                leading=10,
                fontWeight='Bold',
                textColor=colors.white
            )
            
            table_body_style = ParagraphStyle(
                'TableBody',
                parent=styles['Normal'],
                fontSize=7.5,
                leading=9.5,
                textColor=colors.HexColor('#1F2937')
            )

            story = []

            if self.report_type == "threat_incident":
                self._build_single_threat_report(story, title_style, subtitle_style, section_heading_style, body_style, table_header_style, table_body_style, meta_style)
            elif self.report_type == "executive":
                self._build_executive_report(story, title_style, subtitle_style, section_heading_style, body_style, table_header_style, table_body_style, meta_style)
            elif self.report_type == "incidents":
                self._build_incidents_report(story, title_style, body_style, section_heading_style, table_header_style, table_body_style, meta_style)
            elif self.report_type == "events":
                self._build_events_report(story, title_style, body_style, section_heading_style, table_header_style, table_body_style, meta_style)
            elif self.report_type == "history":
                self._build_history_report(story, title_style, body_style, section_heading_style, table_header_style, table_body_style, meta_style)
            else:
                raise ValueError(f"Unknown report type: {self.report_type}")

            doc.build(story)
            self.finished.emit(self.output_path)
            logger.info(f"PDF report generated successfully: {self.output_path}")
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}", exc_info=True)
            self.error.emit(str(e))

    def _build_single_threat_report(self, story, title_style, subtitle_style, h2_style, body_style, head_style, tbl_body_style, meta_style):
        """Builds a dedicated, executive-grade PDF for a single selected threat incident."""
        if not self.incident_id:
            raise ValueError("No incident ID provided for single threat report generation.")

        inc = self.inc_repo.get_incident(self.incident_id)
        if not inc:
            raise ValueError(f"Incident record not found in database.")

        inc_data = dict(inc)
        events_rows = self.events_repo.get_events_by_incident(self.incident_id)
        actual_counts = self.inc_repo.get_incident_event_counts(self.incident_id)

        c_cnt = actual_counts["created_count"] if actual_counts else inc_data.get("created_count", 0)
        m_cnt = actual_counts["modified_count"] if actual_counts else inc_data.get("modified_count", 0)
        r_cnt = actual_counts["renamed_count"] if actual_counts else inc_data.get("renamed_count", 0)
        d_cnt = actual_counts["deleted_count"] if actual_counts else inc_data.get("deleted_count", 0)

        # Diagnostics log
        logger.info("================ SINGLE THREAT REPORT DIAGNOSTIC ================")
        logger.info(f"Database Path:         {self.db.db_path}")
        logger.info(f"Threat Name:           {inc_data['threat_name']}")
        logger.info(f"Affected Folder:       {inc_data['affected_folder']}")
        logger.info(f"Linked Events Count:   {len(events_rows)}")
        logger.info("=================================================================")

        # 1. Document Title / Header
        story.append(Paragraph("RANSOMGUARD EDR", title_style))
        story.append(Paragraph("SECURITY INCIDENT REPORT", subtitle_style))
        story.append(Paragraph(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} | Host: {socket.gethostname()} | User: {getpass.getuser()}", meta_style))
        story.append(Spacer(1, 10))

        # 2. Incident Summary Table
        story.append(Paragraph("1. Incident Summary", h2_style))
        sev = inc_data.get("severity", "HIGH").upper()
        sev_color = "#EF4444" if sev in ("CRITICAL", "HIGH") else "#F59E0B"
        verdict_str = inc_data.get("verdict") or "UNKNOWN"
        
        summary_grid = [
            [
                Paragraph("<b>Threat Activity:</b>", body_style),
                Paragraph(f"<b>{inc_data.get('threat_name', 'Security Threat')}</b>", body_style),
                Paragraph("<b>Severity:</b>", body_style),
                Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", body_style)
            ],
            [
                Paragraph("<b>Risk Score:</b>", body_style),
                Paragraph(f"<b>{inc_data.get('risk_score', 0)} / 100</b>", body_style),
                Paragraph("<b>Analysis Verdict:</b>", body_style),
                Paragraph(f"<b>{verdict_str}</b>", body_style)
            ],
            [
                Paragraph("<b>Current Status:</b>", body_style),
                Paragraph(f"<b>{inc_data.get('status', 'ACTIVE')}</b>", body_style),
                Paragraph("<b>Protection Scope:</b>", body_style),
                Paragraph(f"{', '.join(self.db.get_active_drives())}", body_style)
            ],
            [
                Paragraph("<b>Detection Time:</b>", body_style),
                Paragraph(f"{inc_data.get('detection_time', '-')}", body_style),
                Paragraph("<b>Engine Pipeline:</b>", body_style),
                Paragraph("Unified File & Behavior Engine", body_style)
            ]
        ]
        t_summary = Table(summary_grid, colWidths=[100, 170, 95, 175])
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F9FAFB')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(t_summary)
        story.append(Spacer(1, 8))

        # 3. Affected Location
        story.append(Paragraph("2. Affected Location", h2_style))
        loc_grid = [
            [Paragraph("<b>Affected Folder:</b>", body_style), Paragraph(inc_data.get("affected_folder") or "-", body_style)],
            [Paragraph("<b>Affected File(s):</b>", body_style), Paragraph(inc_data.get("affected_file") or "Multiple Files", body_style)],
            [Paragraph("<b>Full Target Path:</b>", body_style), Paragraph(inc_data.get("full_path") or inc_data.get("affected_folder") or "-", body_style)]
        ]
        t_loc = Table(loc_grid, colWidths=[120, 420])
        t_loc.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F9FAFB')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(t_loc)
        story.append(Spacer(1, 8))

        # 4. Activity Statistics
        story.append(Paragraph("3. Activity Statistics (Database Audit)", h2_style))
        stats_grid = [
            [
                Paragraph("<b>Files Created:</b>", body_style), Paragraph(f"<font color='#22C55E'><b>{c_cnt}</b></font>", body_style),
                Paragraph("<b>Files Modified:</b>", body_style), Paragraph(f"<font color='#3B82F6'><b>{m_cnt}</b></font>", body_style)
            ],
            [
                Paragraph("<b>Files Renamed:</b>", body_style), Paragraph(f"<font color='#F59E0B'><b>{r_cnt}</b></font>", body_style),
                Paragraph("<b>Files Deleted:</b>", body_style), Paragraph(f"<font color='#EF4444'><b>{d_cnt}</b></font>", body_style)
            ]
        ]
        t_stats = Table(stats_grid, colWidths=[120, 150, 120, 150])
        t_stats.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F9FAFB')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(t_stats)
        story.append(Spacer(1, 8))

        # 5. Detection & Process Attribution
        story.append(Paragraph("4. Detection & Process Attribution", h2_style))
        proc_name = inc_data.get("process_name")
        attr_status = inc_data.get("attribution_status")
        proc_pid = inc_data.get("process_pid")
        if proc_name and proc_name not in ("Unknown", "Unknown Process"):
            pid_part = f" (PID: {proc_pid})" if proc_pid else ""
            status_part = f" [{attr_status}]" if attr_status else ""
            proc_str = f"{proc_name}{pid_part}{status_part}"
        else:
            proc_str = "Unknown — attribution unavailable"

        evidence_content = inc_data.get("evidence") or "Behavioral filesystem telemetry correlated in sliding window."
        det_grid = [
            [Paragraph("<b>Detection Reason:</b>", body_style), Paragraph(inc_data.get("detection_reason") or "Suspicious behavioral pattern matched EDR detection rules.", body_style)],
            [Paragraph("<b>Correlated Evidence:</b>", body_style), Paragraph(evidence_content.replace("\n", "<br/>"), body_style)],
            [Paragraph("<b>Detection Method:</b>", body_style), Paragraph("Unified Static File Analysis + Real-time Telemetry Heuristics", body_style)],
            [Paragraph("<b>Attributed Process:</b>", body_style), Paragraph(proc_str, body_style)],
            [Paragraph("<b>Capabilities Status:</b>", body_style), Paragraph("Hashing: Active | PE Analysis: Active | YARA: NOT_CONFIGURED | Reputation: NOT_AVAILABLE", body_style)]
        ]
        t_det = Table(det_grid, colWidths=[120, 420])
        t_det.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F9FAFB')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(t_det)
        story.append(Spacer(1, 8))

        # 6. Protection & Recommendations
        story.append(Paragraph("5. Protection & Action Recommendation", h2_style))
        recom_text = inc_data.get("recommendation") or "Review affected files and restore uncorrupted copies from verified backup."
        prot_grid = [
            [Paragraph("<b>Protection Action:</b>", body_style), Paragraph("ALERT_GENERATED (Real-time telemetry logged & audited)", body_style)],
            [Paragraph("<b>Recommendation:</b>", body_style), Paragraph(recom_text, body_style)]
        ]
        t_prot = Table(prot_grid, colWidths=[120, 420])
        t_prot.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F9FAFB')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(t_prot)
        story.append(Spacer(1, 10))

        # 7. Affected File Events Timeline Table
        story.append(Paragraph(f"6. Affected Files Timeline ({len(events_rows)} Events Logged)", h2_style))
        if not events_rows:
            story.append(Paragraph("⚪ No individual file events linked directly to this incident.", body_style))
            return

        tbl_data = [
            [
                Paragraph("Timestamp (UTC)", head_style),
                Paragraph("Operation", head_style),
                Paragraph("Target Path", head_style),
                Paragraph("Description", head_style),
                Paragraph("Ext", head_style),
                Paragraph("Size", head_style)
            ]
        ]
        
        for r in events_rows:
            ev_type = r["event_type"]
            dest = r["dest_path"]
            if ev_type == "RENAME" and dest:
                desc = f"Renamed to: {os.path.basename(dest)}"
            elif ev_type == "CREATE":
                desc = "New file created"
            elif ev_type == "MODIFY":
                desc = "File contents modified"
            elif ev_type == "DELETE":
                desc = "File deleted"
            else:
                desc = "Filesystem action"

            from ui.components.tables import format_file_size
            size_b = r["file_size"]
            size_str = format_file_size(size_b)

            tbl_data.append([
                Paragraph(str(r["timestamp"]), tbl_body_style),
                Paragraph(ev_type, tbl_body_style),
                Paragraph(str(r["src_path"]), tbl_body_style),
                Paragraph(desc, tbl_body_style),
                Paragraph(str(r["extension"] or "-"), tbl_body_style),
                Paragraph(size_str, tbl_body_style)
            ])

        t_timeline = Table(tbl_data, colWidths=[95, 60, 210, 95, 35, 45])
        t_timeline.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#161B22')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#F9FAFB'), colors.HexColor('#F3F4F6')]),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(t_timeline)

    def _build_executive_report(self, story, title_style, subtitle_style, h2_style, body_style, head_style, tbl_body_style, meta_style):
        """Generates a comprehensive executive summary report from live database metrics."""
        drives = self.db.get_active_drives()
        drives_str = ", ".join(drives) if drives else "None"
        
        scope_inc_clause, scope_inc_params = self.db.get_active_scope_clause("affected_folder")
        incidents_rows = self.db.execute_read(f"SELECT * FROM incidents WHERE {scope_inc_clause} ORDER BY detection_time DESC", tuple(scope_inc_params))
        
        scope_ev_clause, scope_ev_params = self.db.get_active_scope_clause("src_path")
        events_rows = self.db.execute_read(f"SELECT * FROM file_events WHERE {scope_ev_clause} ORDER BY timestamp DESC LIMIT 500", tuple(scope_ev_params))

        # Diagnostic log
        logger.info("================ EXECUTIVE REPORT DIAGNOSTIC ================")
        logger.info(f"Database Path:         {self.db.db_path}")
        logger.info(f"Protected Scope:       {drives_str}")
        logger.info(f"Incidents Found:       {len(incidents_rows)}")
        logger.info(f"Events Found:          {len(events_rows)}")
        logger.info("=============================================================")

        # Document Header
        story.append(Paragraph("RANSOMGUARD EDR", title_style))
        story.append(Paragraph("EXECUTIVE SECURITY SUMMARY REPORT", subtitle_style))
        story.append(Paragraph(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} | Host: {socket.gethostname()} | User: {getpass.getuser()} | OS: {platform.system()} {platform.release()}", meta_style))
        story.append(Paragraph(f"Active Protected Partition Scope: <b>{drives_str}</b>", meta_style))
        story.append(Spacer(1, 10))

        # Summary KPIs
        crit_count = sum(1 for r in incidents_rows if r["severity"].upper() == "CRITICAL")
        high_count = sum(1 for r in incidents_rows if r["severity"].upper() == "HIGH")
        med_count = sum(1 for r in incidents_rows if r["severity"].upper() == "MEDIUM")
        resolved_count = sum(1 for r in incidents_rows if r["status"].upper() == "RESOLVED")
        active_count = len(incidents_rows) - resolved_count

        kpi_grid = [
            [
                Paragraph("<b>Total Security Incidents:</b>", body_style), Paragraph(f"<b>{len(incidents_rows)}</b>", body_style),
                Paragraph("<b>Active Threats:</b>", body_style), Paragraph(f"<font color='#EF4444'><b>{active_count}</b></font>", body_style)
            ],
            [
                Paragraph("<b>Critical Severity:</b>", body_style), Paragraph(f"<font color='#EF4444'><b>{crit_count}</b></font>", body_style),
                Paragraph("<b>Resolved Threats:</b>", body_style), Paragraph(f"<font color='#22C55E'><b>{resolved_count}</b></font>", body_style)
            ],
            [
                Paragraph("<b>High Severity:</b>", body_style), Paragraph(f"<font color='#F59E0B'><b>{high_count}</b></font>", body_style),
                Paragraph("<b>Monitored Events:</b>", body_style), Paragraph(f"<b>{len(events_rows)}</b>", body_style)
            ]
        ]
        t_kpi = Table(kpi_grid, colWidths=[140, 130, 140, 130])
        t_kpi.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F9FAFB')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(t_kpi)
        story.append(Spacer(1, 10))

        # Recent Incidents Section
        story.append(Paragraph(f"Recent Correlated Security Incidents ({len(incidents_rows)} in Scope)", h2_style))
        if not incidents_rows:
            story.append(Paragraph("🟢 No security incidents have been detected within the active partition scope.", body_style))
        else:
            inc_tbl = [
                [
                    Paragraph("Severity", head_style),
                    Paragraph("Threat Name", head_style),
                    Paragraph("Detection Time", head_style),
                    Paragraph("Location", head_style),
                    Paragraph("Process", head_style),
                    Paragraph("Status", head_style),
                    Paragraph("Risk", head_style)
                ]
            ]
            for row in incidents_rows[:20]:
                r = dict(row)
                sev_str = r["severity"].upper()
                s_color = "#EF4444" if sev_str in ("CRITICAL", "HIGH") else "#F59E0B"
                pname = r["process_name"]
                attr_status = r.get("attribution_status")
                proc_pid = r.get("process_pid")
                if pname and pname not in ("Unknown", "Unknown Process"):
                    pid_part = f" ({proc_pid})" if proc_pid else ""
                    p_display = f"{pname}{pid_part}"
                else:
                    p_display = "Unknown"

                inc_tbl.append([
                    Paragraph(f"<font color='{s_color}'><b>{sev_str}</b></font>", tbl_body_style),
                    Paragraph(r["threat_name"], tbl_body_style),
                    Paragraph(r["detection_time"], tbl_body_style),
                    Paragraph(r.get("full_path") or r.get("affected_folder") or "-", tbl_body_style),
                    Paragraph(p_display, tbl_body_style),
                    Paragraph(r["status"], tbl_body_style),
                    Paragraph(f"{r['risk_score']} / 100", tbl_body_style)
                ])

            t_inc = Table(inc_tbl, colWidths=[55, 85, 90, 130, 80, 45, 55])
            t_inc.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#161B22')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#F9FAFB'), colors.HexColor('#F3F4F6')]),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(t_inc)

        story.append(Spacer(1, 10))

        # Recent Events Sample
        story.append(Paragraph(f"Recent File System Telemetry Events (showing {min(len(events_rows), 25)} of {len(events_rows)})", h2_style))
        if not events_rows:
            story.append(Paragraph("⚪ No file activity logged within the active scope.", body_style))
        else:
            ev_tbl = [
                [
                    Paragraph("Timestamp (UTC)", head_style),
                    Paragraph("Operation", head_style),
                    Paragraph("File Path", head_style),
                    Paragraph("Description", head_style),
                    Paragraph("Ext", head_style),
                    Paragraph("Size", head_style)
                ]
            ]
            for row in events_rows[:25]:
                r = dict(row)
                ev_type = r["event_type"]
                dest = r["dest_path"]
                desc = f"Renamed to: {os.path.basename(dest)}" if (ev_type == "RENAME" and dest) else f"File {ev_type.lower()}"
                from ui.components.tables import format_file_size
                size_b = r["file_size"]
                size_str = format_file_size(size_b)

                ev_tbl.append([
                    Paragraph(str(r["timestamp"]), tbl_body_style),
                    Paragraph(ev_type, tbl_body_style),
                    Paragraph(str(r["src_path"]), tbl_body_style),
                    Paragraph(desc, tbl_body_style),
                    Paragraph(str(r["extension"] or "-"), tbl_body_style),
                    Paragraph(size_str, tbl_body_style)
                ])

            t_ev = Table(ev_tbl, colWidths=[95, 60, 210, 95, 35, 45])
            t_ev.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#161B22')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#F9FAFB'), colors.HexColor('#F3F4F6')]),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(t_ev)

    def _build_incidents_report(self, story, title_style, body_style, h2_style, head_style, tbl_body_style, meta_style):
        drives = self.db.get_active_drives()
        drives_str = ", ".join(drives) if drives else "None"
        
        story.append(Paragraph("RansomGuard EDR - Security Incidents Report", title_style))
        story.append(Paragraph(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} | Host: {socket.gethostname()}", meta_style))
        story.append(Paragraph(f"Protected Drives Scope: <b>{drives_str}</b>", body_style))
        story.append(Spacer(1, 8))

        scope_clause, scope_params = self.db.get_active_scope_clause("affected_folder")
        where_clause = f"WHERE {scope_clause}"
            
        query = f"""
            SELECT id, threat_name, severity, risk_score, detection_time, status, 
                   affected_folder, affected_file, full_path, process_pid, process_name, recommendation
            FROM incidents
            {where_clause}
            ORDER BY detection_time DESC
        """
        rows = self.db.execute_read(query, tuple(scope_params))
        
        logger.info("================ INCIDENTS REPORT DIAGNOSTIC ================")
        logger.info(f"Database Path:         {self.db.db_path}")
        logger.info(f"Protected Scope:       {drives_str}")
        logger.info(f"Incidents Retrieved:   {len(rows)}")
        logger.info("=============================================================")

        story.append(Paragraph(f"Total Correlated Security Incidents: <b>{len(rows)}</b>", meta_style))
        story.append(Spacer(1, 8))
        
        if not rows:
            story.append(Paragraph("🟢 No security incidents have been recorded within the active scope.", meta_style))
            return
            
        table_data = [
            [
                Paragraph("Severity", head_style),
                Paragraph("Threat Name", head_style),
                Paragraph("Time", head_style),
                Paragraph("Location / Path", head_style),
                Paragraph("Process", head_style),
                Paragraph("Status", head_style),
                Paragraph("Risk", head_style)
            ]
        ]
        
        for row in rows:
            r = dict(row)
            sev = r["severity"].upper()
            sev_color = "#EF4444" if sev in ("CRITICAL", "HIGH") else "#F59E0B"
            sev_html = f"<font color='{sev_color}'><b>{sev}</b></font>"
            
            pname = r["process_name"]
            if pname and pname not in ("Unknown", "Unknown Process"):
                proc_desc = pname
            else:
                proc_desc = "Unknown"
            
            loc_str = r.get("full_path") or r.get("affected_folder") or "-"

            table_data.append([
                Paragraph(sev_html, tbl_body_style),
                Paragraph(r["threat_name"], tbl_body_style),
                Paragraph(r["detection_time"], tbl_body_style),
                Paragraph(loc_str, tbl_body_style),
                Paragraph(proc_desc, tbl_body_style),
                Paragraph(r["status"], tbl_body_style),
                Paragraph(f"{r['risk_score']} / 100", tbl_body_style)
            ])
            
        table = Table(table_data, colWidths=[55, 85, 90, 130, 80, 45, 55])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#161B22')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#F9FAFB'), colors.HexColor('#F3F4F6')]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(table)

    def _build_events_report(self, story, title_style, body_style, h2_style, head_style, tbl_body_style, meta_style):
        drives = self.db.get_active_drives()
        drives_str = ", ".join(drives) if drives else "None"
        
        story.append(Paragraph("RansomGuard EDR - System File Events Log", title_style))
        story.append(Paragraph(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} | Host: {socket.gethostname()}", meta_style))
        story.append(Paragraph(f"Protected Drives Scope: <b>{drives_str}</b>", body_style))
        story.append(Spacer(1, 8))

        scope_clause, scope_params = self.db.get_active_scope_clause("src_path")
        where_clause = f"WHERE {scope_clause}"
            
        query = f"""
            SELECT timestamp, event_type, src_path, dest_path, extension, file_size
            FROM file_events
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT 500
        """
        rows = self.db.execute_read(query, tuple(scope_params))
        
        logger.info("================ EVENTS REPORT DIAGNOSTIC ================")
        logger.info(f"Database Path:         {self.db.db_path}")
        logger.info(f"Protected Scope:       {drives_str}")
        logger.info(f"Events Retrieved:      {len(rows)}")
        logger.info("==========================================================")

        story.append(Paragraph(f"Recent Monitored File Events (showing up to 500): <b>{len(rows)}</b>", meta_style))
        story.append(Spacer(1, 8))
        
        if not rows:
            story.append(Paragraph("⚪ No file activity logged within the active scope.", meta_style))
            return
            
        table_data = [
            [
                Paragraph("Timestamp (UTC)", head_style),
                Paragraph("Operation", head_style),
                Paragraph("File Path", head_style),
                Paragraph("Description", head_style),
                Paragraph("Ext", head_style),
                Paragraph("Size", head_style)
            ]
        ]
        
        for row in rows:
            r = dict(row)
            ev_type = r["event_type"]
            dest = r["dest_path"]
            
            if ev_type == "RENAME" and dest:
                desc = f"Renamed to: {os.path.basename(dest)}"
            elif ev_type == "CREATE":
                desc = "New file created"
            elif ev_type == "MODIFY":
                desc = "File contents modified"
            elif ev_type == "DELETE":
                desc = "File deleted"
            else:
                desc = "Filesystem action"
                
            from ui.components.tables import format_file_size
            size_b = r["file_size"]
            size_str = format_file_size(size_b)
            
            table_data.append([
                Paragraph(str(r["timestamp"]), tbl_body_style),
                Paragraph(ev_type, tbl_body_style),
                Paragraph(str(r["src_path"]), tbl_body_style),
                Paragraph(desc, tbl_body_style),
                Paragraph(str(r["extension"] or "-"), tbl_body_style),
                Paragraph(size_str, tbl_body_style)
            ])
            
        table = Table(table_data, colWidths=[95, 60, 210, 95, 35, 45])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#161B22')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#F9FAFB'), colors.HexColor('#F3F4F6')]),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(table)

    def _build_history_report(self, story, title_style, body_style, h2_style, head_style, tbl_body_style, meta_style):
        story.append(Paragraph("RansomGuard EDR - EDR Audit History Log", title_style))
        story.append(Paragraph(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} | Host: {socket.gethostname()}", meta_style))
        story.append(Spacer(1, 8))

        query = """
            SELECT timestamp, event_type, severity, description, target, action_taken
            FROM history_log
            ORDER BY timestamp DESC
            LIMIT 500
        """
        rows = self.db.execute_read(query)
        
        story.append(Paragraph(f"EDR Administrative History Logs (showing up to 500): <b>{len(rows)}</b>", meta_style))
        story.append(Spacer(1, 8))
        
        if not rows:
            story.append(Paragraph("⚪ No audit history logs recorded.", meta_style))
            return
            
        table_data = [
            [
                Paragraph("Timestamp (UTC)", head_style),
                Paragraph("Event Type", head_style),
                Paragraph("Severity", head_style),
                Paragraph("Description", head_style),
                Paragraph("Target / Path", head_style),
                Paragraph("Action Taken", head_style)
            ]
        ]
        
        for row in rows:
            r = dict(row)
            table_data.append([
                Paragraph(str(r["timestamp"]), tbl_body_style),
                Paragraph(r["event_type"], tbl_body_style),
                Paragraph(r["severity"], tbl_body_style),
                Paragraph(r["description"], tbl_body_style),
                Paragraph(str(r["target"] or "-"), tbl_body_style),
                Paragraph(str(r["action_taken"] or "-"), tbl_body_style)
            ])
            
        table = Table(table_data, colWidths=[95, 80, 45, 172, 70, 78])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#161B22')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#F9FAFB'), colors.HexColor('#F3F4F6')]),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(table)
