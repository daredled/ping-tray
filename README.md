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
The loss over the last hour is also shown for context (tooltip, menu and notifications), but
the color is based only on the sliding window.
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
| `lan_enabled`          | `false`   | Discover other Ping Tray PCs on the LAN (see below)    |
| `lan_name`             | hostname  | Name this PC is shown with to the others               |
| `lan_port`             | `50505`   | UDP port for discovery and TCP port for speed tests    |
| `lan_secret`           | `""`      | Shared password; peers must use the same one to test   |
| `speedtest_seconds`    | `5`       | Duration of each direction of a speed test (max 30)    |

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

## LAN peers and speed test

With `"lan_enabled": true` on two or more PCs of the same network, each Ping Tray announces
itself and the right-click menu gets a **LAN peers** submenu listing the others. Each peer has:

- **Run speed test**: measures TCP throughput in both directions (↓ from the peer to you, ↑
  from you to the peer, `speedtest_seconds` each) plus the latency, and shows the result as a
  notification and in the submenu. It measures the bottleneck between both PCs (Wi-Fi of
  either one, switch, cables), so it's handy to tell e.g. "the laptop on Wi-Fi only gets
  200 Mbps".
- **Ping this peer**: monitors that PC instead of `target`, with the same colors and
  thresholds. Click it again (or reload settings with LAN off) to go back to `target`.

How it works: every minute each instance broadcasts a UDP beacon on `lan_port`, and answers
right away the first beacon of a new peer, so a PC that starts Ping Tray sees the others within
a second. On quit it says goodbye and disappears from the others' list at once; a PC that is
turned off or loses the network disappears after ~2.5 min. Speed tests use a TCP connection on `lan_port` (or a
free port if it is taken, e.g. by a second instance on the same PC). Each PC serves one test
at a time, capped at 30 s per direction. If you set `lan_secret`, only peers with the same
secret can run tests against you.

**Windows Firewall.** The first time it runs with LAN enabled, Windows asks whether to allow
`pythonw.exe` (or `PingTray.exe`) on the network: allow it on **private networks**. The
network must be marked as *Private* in Windows settings (on *Public* networks the firewall
blocks discovery). If you dismissed the prompt, allow the program under *Windows Security →
Firewall & network protection → Allow an app through firewall*. Running from source needs
`lan.py` next to `ping_tray.py`.

**Testing without a second PC.** `lan.py` also runs as a console node, with no tray icon:

```powershell
uv run lan.py                          # announce this node and print the peers it sees
uv run lan.py --test DESKTOP-SALA      # run a speed test against a peer (name or IP) and exit
uv run lan.py --help                   # --name, --port, --secret, --seconds
```

Run it next to the tray app on the same PC: it appears in **LAN peers** as `<hostname>-cli`,
so you can test against it from the menu, and vice versa. It's also handy to diagnose a real
network: if the console node sees no peers, the problem is the firewall or the broadcast,
not the tray app. On the same PC the speeds are meaningless (the traffic never leaves the
machine).

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
