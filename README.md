# RansomGuard EDR - Lightweight Windows Endpoint Detection & Response

RansomGuard is a fully functional, production-style Windows desktop EDR agent built to actively defend folder directories against ransomware activity. It leverages real Windows API partition detection, multi-threaded filesystem observers, process telemetry analysis, and database transaction WAL logging to operate in real-time with **zero UI lag** under extreme event volume.

---

## ⚡ Performance Architecture

To avoid UI lockups, memory exhaustion, and database write congestion, RansomGuard operates on a strict pipelined separation of concerns:
1. **Pipelined Observability**: File activity is captured by a background thread wrapping `watchdog` and queued. Active processes and recent CPU/disk I/O rates are monitored by a background thread wrapping `psutil`.
2. **Backpressure Events Queue**: Telemetry events enter a bounded queue buffer to protect memory usage during event storms.
3. **Transaction Batch Processing**: A background consumer thread pulls batches (up to 200 events every 200ms), evaluates heuristics rules, groups operations into unified incidents, and performs a single SQLite write transaction.
4. **Asynchronous Heavy Work**: Folder scans, PDF executive report rendering, and CSV exports are delegated to dedicated background worker threads.
5. **Throttled GUI Updates**: Dashboard counters, gauges, and line charts update on controlled intervals (500ms) while critical threat notifications bypass throttling and toast immediately.
6. **Qt Model/View Layout**: Log tables utilize optimized custom `QAbstractTableModel` objects to stream thousands of events with zero rendering bottlenecks.

---

## 🚀 Getting Started

### 1. Installation
RansomGuard requires Python 3.x. Install EDR agent dependencies using pip:
```bash
pip install -r requirements.txt
```

### 2. Launching RansomGuard
Execute the EDR main entrypoint:
```bash
python app.py
```
On the first startup, RansomGuard will automatically:
- Create and schema-initialize `ransomguard.db` in WAL mode.
- Create a folder named `monitored_test` inside the application directory.
- Register `monitored_test` as an actively monitored folder tree root.

---

## 🧪 Safe Ransomware Simulation Test

To trigger and verify RansomGuard's behavioral heuristics, we can simulate ransomware-like activities safely:

1. Launch RansomGuard (`python app.py`).
2. Open the **Live Protection** tab in the UI to watch events stream.
3. In a shell, navigate to the `monitored_test/` directory.
4. Execute a quick safe test to simulate mass creation of files and subsequent encryption renames:
   ```powershell
   # PowerShell simulator
   1..50 | ForEach-Object { 
       $path = "monitored_test\sim_file_$_.docx"
       "dummy data content" | Out-File -FilePath $path
   }
   
   # Simulate mass encryption renaming (triggering CRITICAL incident)
   1..50 | ForEach-Object {
       $src = "monitored_test\sim_file_$_.docx"
       $dest = "$src.locked"
       Rename-Item -Path $src -NewName $dest
   }
   ```
5. Observe the EDR response:
   - A native desktop **threat notification toast** is generated.
   - The large **Critical Incident Hero Alert** slides in on the Dashboard.
   - The stats cards update to reflect the creation, modification, and rename events.
   - Click **View Details** or open the **Threat Repository** to see the expanded incident details, including the timeline of affected files, recommended actions, and the attributed process name/PID that executed the writes.
