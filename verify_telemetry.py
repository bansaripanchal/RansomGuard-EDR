import os
import sys
import datetime
from core.database.database import DatabaseManager
from core.database.incidents_repository import IncidentsRepository
from core.database.events_repository import EventsRepository
from core.database.statistics_repository import StatisticsRepository

def print_telemetry_status(db_path=None):
    db = DatabaseManager(db_path) if db_path else DatabaseManager()
    inc_repo = IncidentsRepository(db)
    events_repo = EventsRepository(db)
    stats_repo = StatisticsRepository(db)

    # 1. Total events in file_events table
    tot_row = db.execute_read_one("SELECT COUNT(*) as cnt FROM file_events")
    total_events = tot_row["cnt"] if tot_row else 0

    # 2. Current month events
    today = datetime.date.today()
    start_of_month = today.replace(day=1).strftime("%Y-%m-%d 00:00:00")
    if today.month == 12:
        next_month_start = datetime.date(today.year + 1, 1, 1).strftime("%Y-%m-%d 00:00:00")
    else:
        next_month_start = datetime.date(today.year, today.month + 1, 1).strftime("%Y-%m-%d 00:00:00")
    
    m_row = db.execute_read_one(
        "SELECT COUNT(*) as cnt FROM file_events WHERE timestamp >= ? AND timestamp < ?",
        (start_of_month, next_month_start)
    )
    current_month_events = m_row["cnt"] if m_row else 0

    # 3. Scope / E: events
    scope_clause, scope_params = db.get_active_scope_clause("src_path")
    e_row = db.execute_read_one(f"SELECT COUNT(*) as cnt FROM file_events WHERE {scope_clause}", tuple(scope_params))
    e_events = e_row["cnt"] if e_row else 0

    # 4. Event types counts in scope
    types_row = db.execute_read_one(f"""
        SELECT 
            SUM(CASE WHEN UPPER(event_type) LIKE '%CREATE%' THEN 1 ELSE 0 END) as created,
            SUM(CASE WHEN UPPER(event_type) LIKE '%MODIF%' THEN 1 ELSE 0 END) as modified,
            SUM(CASE WHEN UPPER(event_type) LIKE '%RENAM%' OR UPPER(event_type) LIKE '%MOVE%' THEN 1 ELSE 0 END) as renamed,
            SUM(CASE WHEN UPPER(event_type) LIKE '%DELET%' THEN 1 ELSE 0 END) as deleted
        FROM file_events
        WHERE {scope_clause}
    """, tuple(scope_params))
    
    create_cnt = (types_row["created"] or 0) if types_row else 0
    modify_cnt = (types_row["modified"] or 0) if types_row else 0
    rename_cnt = (types_row["renamed"] or 0) if types_row else 0
    delete_cnt = (types_row["deleted"] or 0) if types_row else 0

    # 5. Oldest / Newest timestamps
    oldest_row = db.execute_read_one("SELECT timestamp FROM file_events ORDER BY id ASC LIMIT 1")
    newest_row = db.execute_read_one("SELECT timestamp FROM file_events ORDER BY id DESC LIMIT 1")
    oldest_ts = oldest_row["timestamp"] if oldest_row else "None"
    newest_ts = newest_row["timestamp"] if newest_row else "None"

    # Monthly aggregation
    monthly = stats_repo.get_monthly_activity()

    print("============================================================")
    print("      RANSOMGUARD TELEMETRY DIAGNOSTIC INFORMATION         ")
    print("============================================================")
    print(f"DATABASE:\n{db.db_path}\n")
    print(f"EVENT TABLE:\nfile_events\n")
    print(f"TOTAL EVENTS:\n{total_events}\n")
    print(f"CURRENT MONTH EVENTS:\n{current_month_events}\n")
    drives = db.get_active_drives()
    drives_str = ", ".join(drives) if drives else "E:"
    print(f"{drives_str} EVENTS:\n{e_events}\n")
    print(f"CREATE EVENTS:\n{create_cnt}\n")
    print(f"MODIFY EVENTS:\n{modify_cnt}\n")
    print(f"RENAME EVENTS:\n{rename_cnt}\n")
    print(f"DELETE EVENTS:\n{delete_cnt}\n")
    print(f"OLDEST EVENT:\n{oldest_ts}\n")
    print(f"NEWEST EVENT:\n{newest_ts}\n")
    print("------------------------------------------------------------")
    # Newest events list
    recent_events = events_repo.get_events(limit=10)
    print("\n------------------------------------------------------------")
    print("NEWEST RECORDED FILE EVENTS:")
    for ev in recent_events:
        ev_dict = dict(ev)
        ev_type = ev_dict["event_type"]
        path_info = ev_dict["src_path"]
        if ev_type == "RENAME" and ev_dict.get("dest_path"):
            path_info = f"{ev_dict['src_path']} -> {ev_dict['dest_path']}"
        print(f"  [{ev_dict['timestamp']}] {ev_type:8s} | Ext: {ev_dict.get('extension', ''):6s} | Size: {ev_dict.get('file_size', 0):6d}B | Path: {path_info}")
    print("============================================================")

if __name__ == "__main__":
    print_telemetry_status()
