import math
from PySide6.QtWidgets import QWidget, QToolTip, QSizePolicy
from PySide6.QtGui import QPainter, QColor, QPen, QBrush, QFont, QLinearGradient, QRadialGradient
from PySide6.QtCore import Qt, QRect, QRectF, QTimer, QPoint, QPointF

class LightweightBarChart(QWidget):
    """
    A custom QPainter-based monthly chart that renders daily filesystem events
    broken down by operation with zero performance overhead.
    """
    def __init__(self, parent=None):
        super(LightweightBarChart, self).__init__(parent)
        self.days_data = [] # List of day dicts
        self.month_title = "Current Month"
        self.max_val = 1.0
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.MinimumExpanding)
        self.setMinimumHeight(320)

        # Colors for operations
        self.col_created = QColor("#22C55E")   # Green
        self.col_modified = QColor("#3B82F6")  # Blue
        self.col_renamed = QColor("#F59E0B")   # Amber
        self.col_deleted = QColor("#EF4444")   # Red

        # Layout metrics cached for hit-testing
        self._left_pad = 45
        self._right_pad = 20
        self._top_pad = 32
        self._bottom_pad = 36

    def set_data(self, data):
        """
        Updates chart with monthly activity data.
        Data can be a dict from StatisticsRepository.get_monthly_activity()
        or a legacy key-value dict.
        """
        if isinstance(data, dict) and "days" in data:
            self.month_title = data.get("month_name", "Current Month")
            self.days_data = data.get("days", [])
            totals = [d.get("total", 0) for d in self.days_data]
            self.max_val = float(max(totals) if totals and max(totals) > 0 else 1.0)
        elif isinstance(data, dict):
            self.days_data = [{"label": str(k), "total": v, "created": 0, "modified": v, "renamed": 0, "deleted": 0} for k, v in data.items()]
            totals = [d["total"] for d in self.days_data]
            self.max_val = float(max(totals) if totals and max(totals) > 0 else 1.0)
        else:
            self.days_data = []
            self.max_val = 1.0

        self.update() # Triggers paintEvent

    def mouseMoveEvent(self, event):
        """Shows interactive tooltip when hovering over daily bars."""
        if not self.days_data:
            super(LightweightBarChart, self).mouseMoveEvent(event)
            return

        w = self.width()
        chart_w = w - self._left_pad - self._right_pad
        num_bars = len(self.days_data)
        if num_bars == 0 or chart_w <= 0:
            return

        pos_x = event.position().x() if hasattr(event, "position") else event.x()
        if pos_x < self._left_pad or pos_x > w - self._right_pad:
            super(LightweightBarChart, self).mouseMoveEvent(event)
            return

        slot_w = chart_w / num_bars
        idx = int((pos_x - self._left_pad) / slot_w)
        if 0 <= idx < len(self.days_data):
            day = self.days_data[idx]
            tip = (
                f"📅 {day.get('label', '')}\n"
                f"Total Events: {day.get('total', 0):,}\n"
                f"  • Created:  {day.get('created', 0):,}\n"
                f"  • Modified: {day.get('modified', 0):,}\n"
                f"  • Renamed:  {day.get('renamed', 0):,}\n"
                f"  • Deleted:  {day.get('deleted', 0):,}"
            )
            global_pt = event.globalPosition().toPoint() if hasattr(event, "globalPosition") else event.globalPos()
            QToolTip.showText(global_pt, tip, self)
        super(LightweightBarChart, self).mouseMoveEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()
        
        left_pad = self._left_pad
        right_pad = self._right_pad
        top_pad = self._top_pad
        bottom_pad = self._bottom_pad

        chart_w = w - left_pad - right_pad
        chart_h = h - top_pad - bottom_pad

        # Draw dark chart background
        painter.fillRect(0, 0, w, h, QColor("#10161D"))
        
        # Draw grid lines & values (3 steps)
        grid_pen = QPen(QColor("#1C2630"), 1, Qt.DashLine)
        painter.setPen(grid_pen)
        label_font = QFont("Segoe UI", 9)
        painter.setFont(label_font)
        
        text_pen = QPen(QColor("#8B98A8"))
        
        # Draw Legend in top header
        legend_font = QFont("Segoe UI", 8, QFont.Bold)
        painter.setFont(legend_font)
        leg_items = [
            ("■ Created", self.col_created),
            ("■ Modified", self.col_modified),
            ("■ Renamed", self.col_renamed),
            ("■ Deleted", self.col_deleted)
        ]
        cur_lx = max(left_pad, w - right_pad - 310)
        for leg_text, leg_col in leg_items:
            painter.setPen(QPen(leg_col))
            painter.drawText(QRect(cur_lx, 8, 75, 16), Qt.AlignLeft | Qt.AlignVCenter, leg_text)
            cur_lx += 78
            
        display_max = max(4.0, self.max_val)
        
        # Draw Y Grid & labels
        painter.setFont(label_font)
        for i in range(4):
            y = top_pad + int((chart_h / 3.0) * i)
            painter.setPen(grid_pen)
            painter.drawLine(left_pad, y, w - right_pad, y)
            
            # Value label
            val_label = int(round(display_max - (display_max / 3.0) * i))
            painter.setPen(text_pen)
            painter.drawText(QRect(5, y - 8, left_pad - 10, 16), Qt.AlignRight | Qt.AlignVCenter, f"{val_label:,}")

        # Baseline axis line
        base_line_y = top_pad + chart_h
        painter.setPen(QPen(QColor("#2B3847"), 1))
        painter.drawLine(left_pad, base_line_y, w - right_pad, base_line_y)

        total_sum = sum(d.get("total", 0) for d in self.days_data) if self.days_data else 0
        if not self.days_data or total_sum == 0:
            painter.setPen(QPen(QColor("#8B98A8")))
            painter.drawText(
                QRect(left_pad, top_pad, chart_w, chart_h),
                Qt.AlignCenter,
                "No filesystem events recorded for this month yet.\nLive monitoring will populate daily bars as activity occurs."
            )
            return

        # Draw Stacked Bars for each day of the month
        num_bars = len(self.days_data)
        if num_bars == 0:
            return
            
        bar_gap = 2 if num_bars > 20 else 4
        bar_w = (chart_w // num_bars) - bar_gap
        if bar_w < 1:
            bar_w = 1

        for idx, day_info in enumerate(self.days_data):
            tot = day_info.get("total", 0)
            x = left_pad + idx * (bar_w + bar_gap)
            
            if tot > 0:
                c_cnt = day_info.get("created", 0)
                m_cnt = day_info.get("modified", 0)
                r_cnt = day_info.get("renamed", 0)
                d_cnt = day_info.get("deleted", 0)
                
                # Proportional heights
                c_h = max(2, int((c_cnt / display_max) * chart_h)) if c_cnt > 0 else 0
                m_h = max(2, int((m_cnt / display_max) * chart_h)) if m_cnt > 0 else 0
                r_h = max(2, int((r_cnt / display_max) * chart_h)) if r_cnt > 0 else 0
                d_h = max(2, int((d_cnt / display_max) * chart_h)) if d_cnt > 0 else 0
                
                base_y = top_pad + chart_h
                painter.setPen(Qt.NoPen)
                
                # Draw Created (Green)
                if c_h > 0:
                    base_y -= c_h
                    painter.setBrush(QBrush(self.col_created))
                    painter.drawRect(x, base_y, bar_w, c_h)
                    
                # Draw Modified (Blue)
                if m_h > 0:
                    base_y -= m_h
                    painter.setBrush(QBrush(self.col_modified))
                    painter.drawRect(x, base_y, bar_w, m_h)
                    
                # Draw Renamed (Amber)
                if r_h > 0:
                    base_y -= r_h
                    painter.setBrush(QBrush(self.col_renamed))
                    painter.drawRect(x, base_y, bar_w, r_h)
                    
                # Draw Deleted (Red)
                if d_h > 0:
                    base_y -= d_h
                    painter.setBrush(QBrush(self.col_deleted))
                    painter.drawRect(x, base_y, bar_w, d_h)

            # Draw X labels: show day number or label periodically (e.g. Day 1, 5, 10, 15, 20, 25, 30)
            day_num = day_info.get("day", idx + 1)
            is_active_day = (tot > 0)
            if day_num == 1 or day_num % 5 == 0 or day_num == num_bars or is_active_day or num_bars <= 10:
                label_txt = day_info.get("label", str(day_num))
                display_txt = label_txt if (day_num == 1 or num_bars <= 10) else str(day_num)
                
                if is_active_day:
                    painter.setPen(QPen(QColor("#E6EDF3")))
                    painter.setFont(QFont("Segoe UI", 9, QFont.Bold))
                else:
                    painter.setPen(text_pen)
                    painter.setFont(label_font)
                    
                painter.drawText(
                    QRect(x - 12, top_pad + chart_h + 6, bar_w + 24, 18),
                    Qt.AlignCenter,
                    display_txt
                )


class SecurityActivityPulseWidget(QWidget):
    r"""
    A modern EDR/SOC live radial network & radar topology visualization widget.

    Structure:
      - Glowing Central Hub Node:
          ◉
          [Total Files Count] (Real partition inventory)
          TOTAL FILES
          Scope: [Selected Drives]
      - Concentric Radar Rings & Crosshair Grid Lines
      - Rotating Faint Radar Scanner Beam
      - 4 Connected Outer Activity Endpoint Nodes (Floating labels, NO RECTANGLES):
          ● CREATED (Top-Right / Green)
          ● MODIFIED (Bottom-Right / Blue)
          ● RENAMED (Bottom-Left / Amber)
          ● DELETED (Top-Left / Red)
      - Radial Connecting Spokes with Node Terminal Dots
      - Bottom Footer: THIS WEEK • Total Events: XXXX
    """
    def __init__(self, parent=None):
        super(SecurityActivityPulseWidget, self).__init__(parent)
        self.total_files = 0
        self.total_files_status = "done"
        self.drive_scope_label = "Scope: C:\\"

        # Current calendar week activity
        self.created = 0
        self.modified = 0
        self.renamed = 0
        self.deleted = 0
        self.total_weekly_events = 0

        # High-contrast cyber SOC colors
        self.col_created = QColor("#22C55E")   # Green
        self.col_modified = QColor("#3B82F6")  # Blue
        self.col_renamed = QColor("#F59E0B")   # Amber
        self.col_deleted = QColor("#EF4444")   # Red

        self.highlighted_node = None
        self._pulse_timer = QTimer(self)
        self._pulse_timer.setSingleShot(True)
        self._pulse_timer.timeout.connect(self._clear_pulse)

        # Radar sweep rotation timer (subtle, non-blocking 40ms timer)
        self._sweep_angle = 0.0
        self._sweep_timer = QTimer(self)
        self._sweep_timer.setInterval(40)
        self._sweep_timer.timeout.connect(self._rotate_sweep)
        self._sweep_timer.start()

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.setMinimumHeight(260)

    def _rotate_sweep(self):
        if self.isVisible():
            self._sweep_angle = (self._sweep_angle + 1.2) % 360.0
            self.update()

    def _clear_pulse(self):
        self.highlighted_node = None
        self.update()

    def pulse_node(self, node_name: str):
        """Briefly highlights the affected node (CREATED, MODIFIED, RENAMED, DELETED)."""
        self.highlighted_node = (node_name or "").upper()
        self._pulse_timer.start(800)
        self.update()

    def set_total_files(self, count: int, status: str = "done"):
        """Updates the central node with real partition file inventory."""
        self.total_files = int(count or 0)
        self.total_files_status = status
        self.update()

    def set_drive_scope(self, drives_str: str):
        r"""Updates the scope subtitle below TOTAL FILES."""
        if not drives_str:
            self.drive_scope_label = "Scope: C:\\"
        else:
            cleaned_parts = [p.strip().rstrip(":\\").upper() + ":\\" for p in str(drives_str).split(",") if p.strip()]
            formatted_scope = " + ".join(cleaned_parts) if cleaned_parts else str(drives_str)
            self.drive_scope_label = f"Scope: {formatted_scope}"
        self.update()

    def set_stats(self, stats: dict):
        """Pulls current calendar week operations breakdown and real inventory from stats dict."""
        if not stats:
            return

        self.created = int(stats.get("week_created", stats.get("events_today_created", 0)) or 0)
        self.modified = int(stats.get("week_modified", stats.get("events_today_modified", 0)) or 0)
        self.renamed = int(stats.get("week_renamed", stats.get("events_today_renamed", 0)) or 0)
        self.deleted = int(stats.get("week_deleted", stats.get("events_today_deleted", 0)) or 0)

        raw_week_total = stats.get("week_total_events")
        if raw_week_total is not None:
            self.total_weekly_events = int(raw_week_total or 0)
        else:
            self.total_weekly_events = self.created + self.modified + self.renamed + self.deleted

        self.update()

    def set_pulse_data(self, total_files: int, total_files_status: str, drive_scope: str, week_stats: dict):
        """Convenience method to update all pulse metrics simultaneously."""
        self.total_files = int(total_files or 0)
        self.total_files_status = total_files_status or "done"
        self.set_drive_scope(drive_scope)
        self.set_stats(week_stats)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()

        footer_h = 24
        canvas_h = h - footer_h

        cx = w / 2.0
        cy = canvas_h / 2.0

        # Calculate responsive radii for central hub and concentric radar rings
        max_r = min(w / 2.0 - 120, canvas_h / 2.0 - 24)
        max_r = max(80, max_r)

        center_radius = min(52, max(42, max_r * 0.38))
        ring1_r = center_radius + (max_r - center_radius) * 0.35
        ring2_r = center_radius + (max_r - center_radius) * 0.68
        node_r  = max_r  # distance to outer node dots

        # ── 1. DRAW CONCENTRIC RADAR RINGS & RADIAL GRID TICK LINES
        # Outer faint radar glow
        glow_grad = QRadialGradient(cx, cy, max_r + 22)
        glow_grad.setColorAt(0.0, QColor(14, 165, 233, 22))
        glow_grad.setColorAt(0.6, QColor(14, 165, 233, 8))
        glow_grad.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(glow_grad))
        painter.drawEllipse(QPointF(cx, cy), max_r + 22, max_r + 22)

        # Concentric Rings
        painter.setBrush(Qt.NoBrush)

        # Ring 3 (Outermost radar perimeter)
        pen_ring3 = QPen(QColor(30, 58, 95, 120), 1, Qt.DashLine)
        painter.setPen(pen_ring3)
        painter.drawEllipse(QPointF(cx, cy), node_r, node_r)

        # Ring 2 (Middle ring)
        pen_ring2 = QPen(QColor(14, 165, 233, 90), 1, Qt.SolidLine)
        painter.setPen(pen_ring2)
        painter.drawEllipse(QPointF(cx, cy), ring2_r, ring2_r)

        # Ring 1 (Inner ring)
        pen_ring1 = QPen(QColor(30, 58, 95, 160), 1, Qt.DotLine)
        painter.setPen(pen_ring1)
        painter.drawEllipse(QPointF(cx, cy), ring1_r, ring1_r)

        # Crosshair lines & diagonal radar ticks
        cross_pen = QPen(QColor(30, 58, 95, 90), 1, Qt.SolidLine)
        painter.setPen(cross_pen)
        # Horizontal & Vertical axes
        painter.drawLine(QPointF(cx - node_r - 10, cy), QPointF(cx + node_r + 10, cy))
        painter.drawLine(QPointF(cx, cy - node_r - 10), QPointF(cx, cy + node_r + 10))

        # Diagonal ticks (45°, 135°, 225°, 315°)
        diag_len = node_r * 0.7071
        painter.drawLine(QPointF(cx - diag_len, cy - diag_len), QPointF(cx + diag_len, cy + diag_len))
        painter.drawLine(QPointF(cx - diag_len, cy + diag_len), QPointF(cx + diag_len, cy - diag_len))

        # ── 2. ROTATING RADAR SWEEP BEAM (subtle high-tech live effect)
        sweep_rad = math.radians(self._sweep_angle)
        sweep_x = cx + node_r * math.cos(sweep_rad)
        sweep_y = cy + node_r * math.sin(sweep_rad)

        sweep_pen = QPen(QColor(56, 189, 248, 70), 1.5)
        painter.setPen(sweep_pen)
        painter.drawLine(QPointF(cx, cy), QPointF(sweep_x, sweep_y))

        # ── 3. DRAW RADIAL SPOKES & OUTSIDE GLOWING NODES (NO RECTANGLES!)
        # Node configuration: (Label, Count, Color, Angle in Deg, Alignment)
        # Angled placement for a live circular network topology:
        # CREATED: ~ -65° (Top-Right)
        # MODIFIED: ~ 25° (Bottom-Right)
        # RENAMED: ~ 115° (Bottom-Left)
        # DELETED: ~ 205° (Top-Left)
        tot = self.total_weekly_events
        nodes_info = [
            ("CREATED", self.created, self.col_created, -65.0, "TR"),
            ("MODIFIED", self.modified, self.col_modified, 25.0, "BR"),
            ("RENAMED", self.renamed, self.col_renamed, 115.0, "BL"),
            ("DELETED", self.deleted, self.col_deleted, 205.0, "TL"),
        ]

        for label, count, color, angle_deg, align_dir in nodes_info:
            rad = math.radians(angle_deg)
            is_highlighted = (self.highlighted_node == label)

            # Node endpoint coordinate on outer ring
            nx = cx + node_r * math.cos(rad)
            ny = cy + node_r * math.sin(rad)

            # Draw Spoke line from center circle boundary to node dot
            spoke_start_x = cx + center_radius * math.cos(rad)
            spoke_start_y = cy + center_radius * math.sin(rad)

            if is_highlighted:
                spoke_pen = QPen(color, 2.5, Qt.SolidLine)
            else:
                c_tint = QColor(color)
                c_tint.setAlpha(130)
                spoke_pen = QPen(c_tint, 1.2, Qt.DashLine if not is_highlighted else Qt.SolidLine)

            painter.setPen(spoke_pen)
            painter.drawLine(QPointF(spoke_start_x, spoke_start_y), QPointF(nx, ny))

            # Terminal dot on center circle
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(color))
            painter.drawEllipse(QPointF(spoke_start_x, spoke_start_y), 2.5, 2.5)

            # ── GLOWING CIRCULAR ENDPOINT NODE (Point nx, ny)
            glow_r = 16 if is_highlighted else 10
            dot_grad = QRadialGradient(nx, ny, glow_r)
            c_glow = QColor(color)
            c_glow.setAlpha(180 if is_highlighted else 90)
            c_transparent = QColor(color)
            c_transparent.setAlpha(0)
            dot_grad.setColorAt(0.0, c_glow)
            dot_grad.setColorAt(1.0, c_transparent)

            painter.setBrush(QBrush(dot_grad))
            painter.drawEllipse(QPointF(nx, ny), glow_r, glow_r)

            # Solid node dot
            dot_radius = 5.5 if is_highlighted else 4.5
            painter.setBrush(QBrush(color))
            painter.drawEllipse(QPointF(nx, ny), dot_radius, dot_radius)

            # Inner white core point
            painter.setBrush(QBrush(QColor("#FFFFFF")))
            painter.drawEllipse(QPointF(nx, ny), 1.5, 1.5)

            # ── FLOATING LABEL & COUNT (OUTSIDE / AROUND THE GRAPH — NO BOXES)
            tick_len = 14
            tx = nx + tick_len * math.cos(rad)
            ty = ny + tick_len * math.sin(rad)

            painter.setPen(QPen(color, 1.0))
            painter.drawLine(QPointF(nx, ny), QPointF(tx, ty))

            pct_val = int(round((count / float(tot)) * 100)) if tot > 0 else 0
            pct_str = f"({pct_val}%)"
            val_str = f"{count:,}"

            label_font = QFont("Segoe UI", 9, QFont.Bold)
            val_font = QFont("Consolas", 11, QFont.Bold)
            pct_font = QFont("Segoe UI", 8, QFont.Normal)

            text_w = 110
            text_h = 32

            if align_dir == "TR": # Top Right (CREATED)
                lx = tx + 4
                ly = ty - 24
            elif align_dir == "BR": # Bottom Right (MODIFIED)
                lx = tx + 4
                ly = ty - 4
            elif align_dir == "BL": # Bottom Left (RENAMED)
                lx = tx - text_w - 4
                ly = ty - 4
            else: # Top Left (DELETED)
                lx = tx - text_w - 4
                ly = ty - 24

            # Clamp label box to ensure zero clipping
            lx = max(6, min(w - text_w - 6, lx))
            ly = max(6, min(canvas_h - text_h - 4, ly))

            # Line 1: Category Name
            painter.setFont(label_font)
            painter.setPen(QPen(color))
            painter.drawText(QRectF(lx, ly, text_w, 16), Qt.AlignLeft | Qt.AlignVCenter, f"● {label}")

            # Line 2: Count + Percentage
            painter.setFont(val_font)
            painter.setPen(QPen(QColor("#FFFFFF")))
            painter.drawText(QRectF(lx, ly + 16, text_w, 16), Qt.AlignLeft | Qt.AlignVCenter, val_str)

            painter.setFont(val_font)
            val_w = painter.fontMetrics().horizontalAdvance(val_str)

            painter.setFont(pct_font)
            painter.setPen(QPen(QColor("#94A3B8")))
            painter.drawText(QRectF(lx + val_w + 6, ly + 16, text_w - val_w - 6, 16), Qt.AlignLeft | Qt.AlignVCenter, pct_str)

        # ── 4. DRAW CENTRAL GLOWING NODE (TOTAL FILES HUB)
        center_rect = QRectF(cx - center_radius, cy - center_radius, center_radius * 2, center_radius * 2)

        # Multi-layer central radial glow
        hub_glow = QRadialGradient(cx, cy, center_radius + 16)
        hub_glow.setColorAt(0.0, QColor(14, 165, 233, 110))
        hub_glow.setColorAt(0.5, QColor(14, 165, 233, 45))
        hub_glow.setColorAt(1.0, QColor(14, 165, 233, 0))
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(hub_glow))
        painter.drawEllipse(QPointF(cx, cy), center_radius + 16, center_radius + 16)

        # Central Dark Hub Circle
        hub_bg = QColor("#0A0F16")
        hub_border = QColor("#0EA5E9") # Cyan glow border
        painter.setPen(QPen(hub_border, 2.0))
        painter.setBrush(QBrush(hub_bg))
        painter.drawEllipse(center_rect)

        # Inner decorative ring
        inner_r = center_radius - 4
        painter.setPen(QPen(QColor("#1E3A5F"), 1.0, Qt.DotLine))
        painter.setBrush(Qt.NoBrush)
        painter.drawEllipse(QPointF(cx, cy), inner_r, inner_r)

        # Central Hub Content: ONLY "ANALYZING" when calculating, or "COUNT" + "TOTAL FILES" when completed
        if self.total_files_status == "calculating":
            painter.setPen(QPen(QColor("#F59E0B")))
            painter.setFont(QFont("Segoe UI", 9, QFont.Bold))
            painter.drawText(QRectF(cx - center_radius + 4, cy - 8, center_radius * 2 - 8, 16), Qt.AlignCenter, "ANALYZING")
        else:
            # Row 1: Real File Count
            painter.setPen(QPen(QColor("#FFFFFF")))
            num_str = f"{self.total_files:,}"
            num_font_size = 16 if len(num_str) <= 6 else (14 if len(num_str) <= 8 else 12)
            painter.setFont(QFont("Segoe UI", num_font_size, QFont.Bold))
            painter.drawText(QRectF(cx - center_radius + 4, cy - 14, center_radius * 2 - 8, 20), Qt.AlignCenter, num_str)

            # Row 2: TOTAL FILES
            painter.setPen(QPen(QColor("#94A3B8")))
            painter.setFont(QFont("Segoe UI", 8.5, QFont.Bold))
            painter.drawText(QRectF(cx - center_radius + 4, cy + 8, center_radius * 2 - 8, 14), Qt.AlignCenter, "TOTAL FILES")

        # ── 5. DRAW BOTTOM FOOTER: THIS WEEK SUMMARY
        footer_rect = QRectF(0, h - footer_h, w, footer_h)
        if tot > 0:
            footer_text = f"THIS WEEK   •   Total Events: {tot:,}"
            painter.setPen(QPen(QColor("#8B98A8")))
            painter.setFont(QFont("Segoe UI", 9, QFont.DemiBold))
            painter.drawText(footer_rect, Qt.AlignCenter, footer_text)
        else:
            painter.setPen(QPen(QColor("#64748B")))
            painter.setFont(QFont("Segoe UI", 9, QFont.Normal))
            painter.drawText(footer_rect, Qt.AlignCenter, "THIS WEEK   •   No filesystem activity recorded")
