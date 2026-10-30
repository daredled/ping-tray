# Ping Tray

Windows tray icon that pings a host (set in `config.json`) and shows a colored sphere based on
the connection quality over the last few minutes: packet loss, average latency and jitter.

| Color  | Condition                                              |
|--------|--------------------------------------------------------|
| Green  | every metric is within its `green_max_*` threshold     |
| Yellow | some metric is above `green_max_*` but within `yellow_max_*` |
| Red    | some metric is above `yellow_max_*`                    |
| Gray   | no data yet                                            |

The final color is the worst of the three metrics, and the status line names the metric(s)
responsible, e.g. `<target>: Unstable connection (jitter)`.

Hovering shows the host, the loss % (lost/sent), the average latency and the jitter.
Left-clicking shows a notification with the app version and the current stats.
Right-clicking shows the version, the same data plus the last RTT, and options to open/reload
the settings and quit.

The version lives in `__version__` in `ping_tray.py`; keep it in sync with `pyproject.toml`
when bumping it.
A Windows notification is sent whenever the color changes.

## Installation (on Windows, not WSL)

Requires [uv](https://docs.astral.sh/uv/). From the project folder:

```powershell
uv sync
uv run --gui-script ping_tray.py   # --gui-script = pythonw, no console window
```

## Configuration (`config.json`)

| Key                    | Default   | Description                                            |
|------------------------|-----------|--------------------------------------------------------|
| `target`               | (required) | IP or hostname to ping                                |
| `interval_seconds`     | `1.0`     | How often a ping is sent                               |
| `timeout_ms`           | `1000`    | Maximum time to wait for a reply (later = lost)        |
| `window_minutes`       | `5`       | Size of the sliding window                             |
| `green_max_loss_pct`   | `0.5`     | Maximum packet loss (%) for green                      |
| `yellow_max_loss_pct`  | `2.0`     | Maximum packet loss (%) for yellow; above this is red  |
| `green_max_rtt_ms`     | `100`     | Maximum average latency (ms) for green                 |
| `yellow_max_rtt_ms`    | `250`     | Maximum average latency (ms) for yellow                |
| `green_max_jitter_ms`  | `20`      | Maximum jitter (ms) for green                          |
| `yellow_max_jitter_ms` | `50`      | Maximum jitter (ms) for yellow                         |
| `notify_on_change`     | `true`    | Notify when the color changes                          |

`target` has no default and must be set. If `config.json` doesn't exist, it is created with an
empty `target`; until you fill it in, the icon stays gray, nothing is pinged and the menu shows
the error. Every other key is optional and falls back to the default above.

After editing the file use **Reload settings** in the menu.

### Why these thresholds

**Packet loss.** At 1 ping/s with a 5 min window there are ~300 samples, so each lost packet
is worth ~0.33 %:

| Lost in 5 min | Loss         | Color  |
|---------------|--------------|--------|
| 0–1           | 0 – 0.33 %   | Green  |
| 2–6           | 0.67 – 2 %   | Yellow |
| 7 or more     | > 2 %        | Red    |

- **Green tolerates 1 lost packet.** Even a healthy connection drops the occasional ping
  (many hosts, especially public DNS servers, deprioritize ICMP). With a 0 % threshold, a connection with ~0.1 % baseline loss
  would show yellow ~26 % of the time; tolerating 1 packet brings that down to ~4 %.
- **Yellow (0.5–2 %)** is real but tolerable loss: browsing is unaffected, but it is already
  above what is recommended for calls (Microsoft Teams asks for < 1 %).
- **Red (> 2 %)** is where video calls, voice and games break up noticeably. A healthy
  connection practically never loses 7 packets in 5 minutes.

For something stricter (e.g. if you take a lot of calls) use `yellow_max_loss_pct: 1.0`.

**Latency** is the average RTT over the window. Below 100 ms nothing is noticeable; 100–250 ms
is felt in games and calls; above 250 ms conversations start talking over each other.

**Jitter** is the average difference between consecutive RTTs: it measures how unstable the
latency is, which is what causes choppy audio and video. Below 20 ms is fine; above 50 ms
calls degrade even when the average latency is low.

**Startup.** Until the window fills up, the loss % used for the color is computed against
the sample count of a full window (300). That way a single lost packet in the first seconds
doesn't turn the icon red, but a full outage does within ~7 seconds. The tooltip still shows
the actual loss %. Latency and jitter are evaluated only after 10 replies, so a slow first
ping doesn't affect the color.

## Start with Windows

`Win + R` → `shell:startup` → create a shortcut there to
`C:\path\ping-tray\.venv\Scripts\pythonw.exe "C:\path\ping-tray\ping_tray.py"`.

## Building an .exe (optional)

An `.exe` doesn't need Python or uv to run, and Windows lists it as **PingTray** (rather than
"Python") in the taskbar settings.

1. **Build on Windows**, not WSL: PyInstaller only produces executables for the OS it runs on.
   Work from a Windows folder (e.g. `C:\Users\<user>\ping-tray`) rather than
   `\\wsl.localhost\...`, which is slower and not supported as the current directory by some
   commands.

2. Open PowerShell in that folder and install the dependencies:

   ```powershell
   uv sync
   ```

3. Build the executable (PyInstaller is installed for this command only, it doesn't become a
   project dependency):

   ```powershell
   uv run --with pyinstaller pyinstaller --noconfirm --onefile --noconsole --name PingTray ping_tray.py
   ```

   - `--onefile`: a single `.exe` (~16 MB) bundling Python and the dependencies.
   - `--noconsole`: no console window.
   - `--noconfirm`: overwrite a previous build without asking.

   It takes under a minute. The result is `dist\PingTray.exe`; the `build\` folder and the
   `PingTray.spec` file are temporary and can be deleted.

4. Copy `dist\PingTray.exe` to its final location, e.g. `C:\Users\<user>\Apps\PingTray\`.
   Copy your `config.json` next to the `.exe`. If there is none, the first run creates one with
   an empty `target`: set it, then use **Reload settings**.

5. Double-click `PingTray.exe`. The sphere appears in the tray (if you don't see it, check the
   hidden icons under the `^` arrow next to the clock).

**Start with Windows:** `Win + R` → `shell:startup` → right-click → *New* → *Shortcut*
→ point it to `C:\Users\<user>\Apps\PingTray\PingTray.exe`.

**Updating:** close the program (right-click → *Quit*), repeat step 3 and replace the `.exe`.
Always keep the same path so Windows remembers that the icon should stay visible.

**Antivirus:** PyInstaller `--onefile` executables sometimes trigger false positives in
Windows Defender. If it gets blocked, build without `--onefile` (which produces a
`dist\PingTray\` folder with the `.exe` and its files) or add an exclusion for that folder.

## License

[MIT](LICENSE)
