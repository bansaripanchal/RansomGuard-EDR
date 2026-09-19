from core.database.database import DatabaseManager
import datetime
import calendar
import logging

logger = logging.getLogger("RansomGuard.StatisticsRepository")

class StatisticsRepository:
    def __init__(self, db_manager=None):
        self.db = db_manager or DatabaseManager()

    def get_dashboard_summary(self):
        """
        Retrieves all key summary counts for the dashboard filtered by the active drive scope.
        """
        try:
            # 1. Monitored events counts for active protected drives
            scope_clause, scope_params = self.db.get_active_scope_clause("src_path")
            events_query = f"""
                SELECT 
                    SUM(CASE WHEN event_type = 'CREATE' THEN 1 ELSE 0 END) as created,
                    SUM(CASE WHEN event_type = 'MODIFY' THEN 1 ELSE 0 END) as modified,
                    SUM(CASE WHEN event_type = 'RENAME' THEN 1 ELSE 0 END) as renamed,
                    SUM(CASE WHEN event_type = 'DELETE' THEN 1 ELSE 0 END) as deleted,
                    COUNT(DISTINCT src_path) as unique_files,
                    COUNT(*) as total_events
                FROM file_events
                WHERE {scope_clause}
            """
            events_row = self.db.execute_read_one(events_query, tuple(scope_params))
            created = (events_row["created"] or 0) if events_row else 0
            modified = (events_row["modified"] or 0) if events_row else 0
            renamed = (events_row["renamed"] or 0) if events_row else 0
            deleted = (events_row["deleted"] or 0) if events_row else 0
            unique_files = (events_row["unique_files"] or 0) if events_row else 0
            total_events = (events_row["total_events"] or 0) if events_row else 0

            # 2. Current calendar week operations breakdown (Monday 00:00:00 to now)
            today = datetime.date.today()
            start_of_week = (today - datetime.timedelta(days=today.weekday())).strftime("%Y-%m-%d 00:00:00")
            week_scope_clause, week_scope_params = self.db.get_active_scope_clause("src_path")
            week_query = f"""
                SELECT 
                    SUM(CASE WHEN event_type = 'CREATE' THEN 1 ELSE 0 END) as week_created,
                    SUM(CASE WHEN event_type = 'MODIFY' THEN 1 ELSE 0 END) as week_modified,
                    SUM(CASE WHEN event_type = 'RENAME' THEN 1 ELSE 0 END) as week_renamed,
                    SUM(CASE WHEN event_type = 'DELETE' THEN 1 ELSE 0 END) as week_deleted,
                    COUNT(*) as week_total
                FROM file_events
                WHERE timestamp >= ? AND {week_scope_clause}
            """
            week_row = self.db.execute_read_one(week_query, (start_of_week, *week_scope_params))
            w_created = (week_row["week_created"] or 0) if week_row else 0
            w_modified = (week_row["week_modified"] or 0) if week_row else 0
            w_renamed = (week_row["week_renamed"] or 0) if week_row else 0
            w_deleted = (week_row["week_deleted"] or 0) if week_row else 0
            w_total = w_created + w_modified + w_renamed + w_deleted

            # 3. Incidents counts (active, blocked/resolved, total, filtered by active drives)
            incidents_clause, incidents_scope_params = self.db.get_active_scope_clause("affected_folder")
            incidents_query = f"""
                SELECT 
                    SUM(CASE WHEN status = 'ACTIVE' AND (dismissed = 0 OR dismissed IS NULL) THEN 1 ELSE 0 END) as active,
                    SUM(CASE WHEN status = 'RESOLVED' AND (dismissed = 0 OR dismissed IS NULL) THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN (dismissed = 0 OR dismissed IS NULL) THEN 1 ELSE 0 END) as total
                FROM incidents
                WHERE {incidents_clause}
            """
            incidents_row = self.db.execute_read_one(incidents_query, tuple(incidents_scope_params))
            active_incidents = (incidents_row["active"] or 0) if incidents_row else 0
            blocked_incidents = (incidents_row["blocked"] or 0) if incidents_row else 0
            total_incidents = (incidents_row["total"] or 0) if incidents_row else 0

            return {
                "events_today_total": unique_files,
                "total_events": total_events,
                "events_today_created": created,
                "events_today_modified": modified,
                "events_today_renamed": renamed,
                "events_today_deleted": deleted,
                "week_created": w_created,
                "week_modified": w_modified,
                "week_renamed": w_renamed,
                "week_deleted": w_deleted,
                "week_total_events": w_total,
                "incidents_active": active_incidents,
                "incidents_total": total_incidents,
                "incidents_blocked": blocked_incidents
            }
        except Exception as e:
            logger.error(f"Error querying dashboard summary: {e}", exc_info=True)
            raise e

    def get_hourly_activity_today(self):
        """
        Returns file event activity grouped by hour for the current day, filtered by active drives.
        """
        start_of_day = datetime.datetime.now(datetime.timezone.utc).date().isoformat() + " 00:00:00"
        scope_clause, scope_params = self.db.get_active_scope_clause("src_path")
        params = [start_of_day] + scope_params

        query = f"""
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
            FROM file_events
            WHERE timestamp >= ? AND {scope_clause}
            GROUP BY hour
            ORDER BY hour ASC
        """
        rows = self.db.execute_read(query, tuple(params))
        # Fill dictionary with hours (00-23)
        activity = {f"{h:02d}": 0 for h in range(24)}
        for r in rows:
            hour_str = r["hour"]
            activity[hour_str] = r["count"]
        return activity

    def get_incident_severity_distribution(self):
        """Returns the distribution of incident severities, filtered by active drives."""
        scope_clause, scope_params = self.db.get_active_scope_clause("affected_folder")

        query = f"""
            SELECT severity, COUNT(*) as count
            FROM incidents
            WHERE (dismissed = 0 OR dismissed IS NULL) AND {scope_clause}
            GROUP BY severity
        """
        rows = self.db.execute_read(query, tuple(scope_params))
        distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for r in rows:
            sev = r["severity"]
            if sev in distribution:
                distribution[sev] = r["count"]
        return distribution

    def get_monthly_activity(self):
        """
        Returns real daily filesystem activity broken down by operation (CREATE, MODIFY, RENAME, DELETE)
        for every day of the current calendar month, filtered by active protected drives.
        Uses a fast single SQLite aggregate query.
        """
        try:
            today = datetime.date.today()
            start_of_month = today.replace(day=1).strftime("%Y-%m-%d 00:00:00")
            _, num_days = calendar.monthrange(today.year, today.month)
            
            if today.month == 12:
                next_month_start = datetime.date(today.year + 1, 1, 1).strftime("%Y-%m-%d 00:00:00")
            else:
                next_month_start = datetime.date(today.year, today.month + 1, 1).strftime("%Y-%m-%d 00:00:00")

            scope_clause, scope_params = self.db.get_active_scope_clause("src_path")
            params = [start_of_month, next_month_start] + scope_params
            
            query = f"""
                SELECT 
                    strftime('%Y-%m-%d', timestamp) as event_date,
                    UPPER(event_type) as event_type, 
                    COUNT(*) as count
                FROM file_events
                WHERE timestamp >= ? AND timestamp < ? AND {scope_clause}
                GROUP BY event_date, event_type
                ORDER BY event_date ASC
            """
            rows = self.db.execute_read(query, tuple(params))
            
            daily_breakdown = {}
            for r in rows:
                d_str = r["event_date"]
                raw_type = (r["event_type"] or "").upper()
                if "CREATE" in raw_type:
                    ev_type = "CREATE"
                elif "MODIF" in raw_type:
                    ev_type = "MODIFY"
                elif "RENAM" in raw_type or "MOVE" in raw_type:
                    ev_type = "RENAME"
                elif "DELET" in raw_type:
                    ev_type = "DELETE"
                else:
                    ev_type = "MODIFY"
                
                cnt = r["count"]
                if d_str not in daily_breakdown:
                    daily_breakdown[d_str] = {"CREATE": 0, "MODIFY": 0, "RENAME": 0, "DELETE": 0, "TOTAL": 0}
                daily_breakdown[d_str][ev_type] += cnt
                daily_breakdown[d_str]["TOTAL"] += cnt

            month_name = today.strftime("%b")
            result = []
            for day in range(1, num_days + 1):
                date_obj = today.replace(day=day)
                date_str = date_obj.strftime("%Y-%m-%d")
                label = f"{month_name} {day}"
                day_data = daily_breakdown.get(date_str, {"CREATE": 0, "MODIFY": 0, "RENAME": 0, "DELETE": 0, "TOTAL": 0})
                result.append({
                    "day": day,
                    "label": label,
                    "date": date_str,
                    "is_today": (date_obj == today),
                    "is_future": (date_obj > today),
                    "created": day_data["CREATE"],
                    "modified": day_data["MODIFY"],
                    "renamed": day_data["RENAME"],
                    "deleted": day_data["DELETE"],
                    "total": day_data["TOTAL"]
                })
                
            return {
                "month_name": today.strftime("%B %Y"),
                "days": result,
                "total_month_events": sum(d["total"] for d in result)
            }
        except Exception as e:
            logger.error(f"Error querying monthly activity: {e}", exc_info=True)
            raise e

    def get_weekly_activity(self):
        """
        Returns file event activity counts for the last 7 days, filtered by active drives.
        """
        scope_clause, scope_params = self.db.get_active_scope_clause("src_path")
            
        query = f"""
            SELECT date(timestamp) as event_date, COUNT(*) as count
            FROM file_events
            WHERE timestamp >= datetime('now', '-7 days') AND {scope_clause}
            GROUP BY event_date
            ORDER BY event_date ASC
        """
        rows = self.db.execute_read(query, tuple(scope_params))
        
        day_counts = {}
        for r in rows:
            day_counts[r["event_date"]] = r["count"]
            
        activity = {}
        today = datetime.date.today()
        for i in range(6, -1, -1):
            d = today - datetime.timedelta(days=i)
            d_str = d.isoformat()
            day_name = d.strftime("%a")
            activity[day_name] = day_counts.get(d_str, 0)
            
        return activity

    def get_weekly_operations_breakdown(self):
        """
        Returns real file creation, modification, rename, and deletion event counts
        for the current calendar week, filtered by the active drive scope.
        """
        try:
            today = datetime.date.today()
            start_of_week = (today - datetime.timedelta(days=today.weekday())).strftime("%Y-%m-%d 00:00:00")
            week_scope_clause, week_scope_params = self.db.get_active_scope_clause("src_path")
            week_query = f"""
                SELECT 
                    SUM(CASE WHEN event_type = 'CREATE' THEN 1 ELSE 0 END) as created,
                    SUM(CASE WHEN event_type = 'MODIFY' THEN 1 ELSE 0 END) as modified,
                    SUM(CASE WHEN event_type = 'RENAME' THEN 1 ELSE 0 END) as renamed,
                    SUM(CASE WHEN event_type = 'DELETE' THEN 1 ELSE 0 END) as deleted,
                    COUNT(*) as total_events
                FROM file_events
                WHERE timestamp >= ? AND {week_scope_clause}
            """
            week_row = self.db.execute_read_one(week_query, (start_of_week, *week_scope_params))
            created = (week_row["created"] or 0) if week_row else 0
            modified = (week_row["modified"] or 0) if week_row else 0
            renamed = (week_row["renamed"] or 0) if week_row else 0
            deleted = (week_row["deleted"] or 0) if week_row else 0
            total = created + modified + renamed + deleted
            return {
                "created": created,
                "modified": modified,
                "renamed": renamed,
                "deleted": deleted,
                "total": total
            }
        except Exception as e:
            logger.error(f"Error querying weekly operations breakdown: {e}", exc_info=True)
            return {"created": 0, "modified": 0, "renamed": 0, "deleted": 0, "total": 0}
