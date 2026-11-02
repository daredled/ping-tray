"""System tray icon that monitors connection quality to a host.

Pings the host set as "target" in config.json and shows a colored sphere based on
packet loss, average latency and jitter over a sliding window (5 minutes by default).
Each metric has green_max_* and yellow_max_* thresholds; the final color is the worst
of the three:

    green   every metric <= green_max_*
    yellow  some metric  <= yellow_max_*
    red     some metric  >  yellow_max_*
    gray    no data yet

Configuration lives in config.json next to the script (or next to the .exe).
"""

import ctypes
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import traceback
from collections import deque
from dataclasses import dataclass
from pathlib import Path

import pystray
from PIL import Image, ImageDraw

import i18n
import lan
from i18n import LocalizedError, t

APP_NAME = "Ping Tray"
__version__ = "0.4.0"  # keep in sync with pyproject.toml

# "target" has no default: the host to ping must be set in config.json.
DEFAULT_CONFIG = {
    "interval_seconds": 1.0,
    "timeout_ms": 1000,
    "window_minutes": 5,
    "green_max_loss_pct": 0.5,
    "yellow_max_loss_pct": 2.0,
    "green_max_rtt_ms": 100,
    "yellow_max_rtt_ms": 250,
    "green_max_jitter_ms": 20,
    "yellow_max_jitter_ms": 50,
    "notify_on_change": True,
    "lan_enabled": False,
    "lan_name": "",  # empty = this PC's hostname
    "lan_port": 50505,
    "lan_secret": "",
    "speedtest_seconds": 5,
    "outage_min_lost": 3,
    "language": "",  # empty = the OS display language
}

LAN_KEYS = ("lan_enabled", "lan_name", "lan_port", "lan_secret")

# Pings sent to a peer to report its latency along with the speed test
SPEEDTEST_PINGS = 5

# (name, config key suffix) of each thresholded metric; the name is translated as metric_<name>
METRICS = (
    ("loss", "loss_pct"),
    ("latency", "rtt_ms"),
    ("jitter", "jitter_ms"),
)

# Minimum replies before latency and jitter are evaluated, so a slow first ping
# (ARP/DNS resolution) doesn't change the color at startup.
MIN_LATENCY_SAMPLES = 10

# Loss over this longer period is shown alongside the window's, for context only (not used for the color)
LOSS_HISTORY_S = 3600

SEVERITY = ("green", "yellow", "red")

COLORS = {
    "green": (46, 184, 76),
    "yellow": (240, 190, 0),
    "red": (220, 45, 45),
    "gray": (140, 140, 140),
}


def app_dir() -> Path:
    if getattr(sys, "frozen", False):  # executable built with PyInstaller
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


CONFIG_PATH = app_dir() / "config.json"


def load_config(previous: dict | None = None) -> tuple[dict, Exception | None]:
    """Returns (config, error).

    On error keeps the previous config, or an idle one (empty target, no pinging) at startup.
    If config.json doesn't exist, it is created with an empty target for the user to fill in.
    An empty target is reported as an error but the rest of the config (e.g. LAN) still applies.
    """
    try:
        if not CONFIG_PATH.exists():
            template = {"target": "", **DEFAULT_CONFIG}
            CONFIG_PATH.write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8")
        user_cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        cfg = {**DEFAULT_CONFIG, **user_cfg}
        cfg["target"] = str(cfg.get("target") or "").strip()
        for key in ("interval_seconds", "window_minutes", "speedtest_seconds"):
            cfg[key] = float(cfg[key])
        cfg["timeout_ms"] = int(cfg["timeout_ms"])
        cfg["outage_min_lost"] = int(cfg["outage_min_lost"])
        if cfg["outage_min_lost"] < 1:
            raise LocalizedError("cfg_outage_min_lost")
        cfg["notify_on_change"] = bool(cfg["notify_on_change"])
        if cfg["interval_seconds"] <= 0 or cfg["window_minutes"] <= 0 or cfg["timeout_ms"] <= 0:
            raise LocalizedError("cfg_positive")
        for _, metric in METRICS:
            green, yellow = f"green_max_{metric}", f"yellow_max_{metric}"
            cfg[green], cfg[yellow] = float(cfg[green]), float(cfg[yellow])
            if cfg[green] > cfg[yellow]:
                raise LocalizedError("cfg_thresholds", green=green, yellow=yellow)
        cfg["lan_enabled"] = bool(cfg["lan_enabled"])
        cfg["lan_name"] = str(cfg["lan_name"] or "").strip() or socket.gethostname()
        cfg["lan_port"] = int(cfg["lan_port"])
        cfg["lan_secret"] = str(cfg["lan_secret"] or "")
        cfg["language"] = str(cfg["language"] or "").strip()
        if not 1 <= cfg["lan_port"] <= 65535:
            raise LocalizedError("cfg_lan_port")
        if not 0 < cfg["speedtest_seconds"] <= lan.MAX_TEST_SECONDS:
            raise LocalizedError("cfg_speedtest", max=lan.MAX_TEST_SECONDS)
        if not cfg["target"]:
            return cfg, LocalizedError("cfg_target")
        return cfg, None
    except (OSError, ValueError, TypeError, AttributeError) as e:  # JSONDecodeError subclasses ValueError
        fallback = previous or {"target": "", **DEFAULT_CONFIG}
        return dict(fallback), e


# --- Ping -------------------------------------------------------------------


class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_ulong),
        ("Status", ctypes.c_ulong),
        ("RoundTripTime", ctypes.c_ulong),
        ("DataSize", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("Data", ctypes.c_void_p),
        ("Options", IP_OPTION_INFORMATION),
    ]


class WindowsPinger:
    """Ping via IcmpSendEcho: needs no admin rights and doesn't depend on the Windows language."""

    PAYLOAD = b"ping-tray-ping-tray-ping-tray-32"

    def __init__(self):
        lib = ctypes.windll.iphlpapi
        lib.IcmpCreateFile.restype = ctypes.c_void_p
        lib.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
        lib.IcmpSendEcho.argtypes = [
            ctypes.c_void_p,  # IcmpHandle
            ctypes.c_ulong,   # DestinationAddress
            ctypes.c_char_p,  # RequestData
            ctypes.c_ushort,  # RequestSize
            ctypes.c_void_p,  # RequestOptions
            ctypes.c_void_p,  # ReplyBuffer
            ctypes.c_ulong,   # ReplySize
            ctypes.c_ulong,   # Timeout
        ]
        lib.IcmpSendEcho.restype = ctypes.c_ulong
        self._lib = lib
        self._handle = lib.IcmpCreateFile()
        self._reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + len(self.PAYLOAD) + 8 + 64
        self._buffer = ctypes.create_string_buffer(self._reply_size)

    def ping(self, host: str, timeout_ms: int) -> float | None:
        """Returns the RTT in ms, or None if the packet was lost."""
        try:
            addr = socket.gethostbyname(host)
        except OSError:
            return None
        dest = int.from_bytes(socket.inet_aton(addr), "little")  # network byte order in memory
        count = self._lib.IcmpSendEcho(
            self._handle, dest, self.PAYLOAD, len(self.PAYLOAD),
            None, self._buffer, self._reply_size, timeout_ms,
        )
        if count == 0:
            return None
        reply = ICMP_ECHO_REPLY.from_buffer(self._buffer)
        if reply.Status != 0:  # IP_SUCCESS
            return None
        return float(reply.RoundTripTime)

    def close(self):
        self._lib.IcmpCloseHandle(self._handle)


class SubprocessPinger:
    """Fallback for Linux (handy for testing outside Windows)."""

    RTT_RE = re.compile(r"time[=<]([\d.]+)")

    def ping(self, host: str, timeout_ms: int) -> float | None:
        timeout_s = max(1, round(timeout_ms / 1000))
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout_s), host],
                capture_output=True, text=True, timeout=timeout_s + 2,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        match = self.RTT_RE.search(result.stdout)
        return float(match.group(1)) if match else 0.0

    def close(self):
        pass


# --- Statistics -------------------------------------------------------------


@dataclass
class Stats:
    sent: int
    lost: int
    avg_rtt: float | None
    last_rtt: float | None
    jitter: float | None  # mean difference between consecutive RTTs
    elapsed_s: float  # time since the first sample (to tell whether the window is full)
    history_sent: int = 0  # over the last LOSS_HISTORY_S
    history_lost: int = 0
    outages: int = 0  # runs of >= outage_min_lost consecutive lost pings in the last LOSS_HISTORY_S
    outage_ongoing: bool = False
    last_outage_s: float | None = None  # duration of the latest outage (so far, if ongoing)
    last_outage_ago_s: float | None = None  # time since it ended

    @property
    def received(self) -> int:
        return self.sent - self.lost

    @property
    def loss_pct(self) -> float:
        return 100.0 * self.lost / self.sent if self.sent else 0.0

    @property
    def history_loss_pct(self) -> float:
        return 100.0 * self.history_lost / self.history_sent if self.history_sent else 0.0


class SampleWindow:
    """Keeps ping results for the sliding window and for LOSS_HISTORY_S, whichever is longer."""

    def __init__(self):
        self._samples: deque[tuple[float, float | None]] = deque()
        self._started: float | None = None
        self._lock = threading.Lock()

    def add(self, rtt: float | None):
        with self._lock:
            now = time.monotonic()
            if self._started is None:
                self._started = now
            self._samples.append((now, rtt))

    def clear(self):
        with self._lock:
            self._samples.clear()
            self._started = None

    def stats(self, window_s: float, outage_min_lost: int = 3) -> Stats:
        with self._lock:
            now = time.monotonic()
            history_cutoff = now - max(window_s, LOSS_HISTORY_S)
            while self._samples and self._samples[0][0] < history_cutoff:
                self._samples.popleft()
            history = [(t, rtt) for t, rtt in self._samples if t >= now - LOSS_HISTORY_S]
            rtts = [rtt for t, rtt in self._samples if t >= now - window_s]
            elapsed = now - self._started if self._started is not None else 0.0
        outages = _find_outages(history, outage_min_lost)
        ongoing = bool(outages) and outages[-1][1] is None
        if outages:
            start, end = outages[-1]
            last_outage_s = (end or now) - start
            last_outage_ago_s = now - end if end is not None else 0.0
        else:
            last_outage_s = last_outage_ago_s = None
        ok = [r for r in rtts if r is not None]
        diffs = [abs(b - a) for a, b in zip(ok, ok[1:])]
        return Stats(
            sent=len(rtts),
            lost=len(rtts) - len(ok),
            avg_rtt=sum(ok) / len(ok) if ok else None,
            last_rtt=rtts[-1] if rtts else None,
            jitter=sum(diffs) / len(diffs) if diffs else None,
            elapsed_s=elapsed,
            history_sent=len(history),
            history_lost=sum(rtt is None for _, rtt in history),
            outages=len(outages),
            outage_ongoing=ongoing,
            last_outage_s=last_outage_s,
            last_outage_ago_s=last_outage_ago_s,
        )


def _find_outages(samples: list[tuple[float, float | None]], min_lost: int) -> list[tuple[float, float | None]]:
    """(start, end) of each run of >= min_lost consecutive lost pings; end is None if ongoing.

    An outage runs from its first lost ping to the next reply.
    """
    outages = []
    run_start, run_len = 0.0, 0
    for t, rtt in samples:
        if rtt is None:
            if run_len == 0:
                run_start = t
            run_len += 1
        else:
            if run_len >= min_lost:
                outages.append((run_start, t))
            run_len = 0
    if run_len >= min_lost:
        outages.append((run_start, None))
    return outages


def _level(value: float, cfg: dict, metric: str) -> int:
    if value <= cfg[f"green_max_{metric}"]:
        return 0
    if value <= cfg[f"yellow_max_{metric}"]:
        return 1
    return 2


def classify(stats: Stats, cfg: dict) -> tuple[str, list[str]]:
    """Returns (state, metrics responsible for that state)."""
    if stats.sent == 0:
        return "gray", []
    window_s = cfg["window_minutes"] * 60
    loss_pct = stats.loss_pct
    if stats.elapsed_s < window_s:
        # Until the window fills up, divide by the sample count of a full window:
        # one lost packet at startup doesn't turn red, but a full outage does within seconds.
        expected = window_s / cfg["interval_seconds"]
        loss_pct = 100.0 * stats.lost / max(stats.sent, expected)
    values = {"loss_pct": loss_pct}
    if stats.received >= MIN_LATENCY_SAMPLES:
        values["rtt_ms"] = stats.avg_rtt
        if stats.jitter is not None:
            values["jitter_ms"] = stats.jitter
    levels = {name: _level(values[metric], cfg, metric) for name, metric in METRICS if metric in values}
    worst = max(levels.values())
    return SEVERITY[worst], [name for name, lvl in levels.items() if lvl == worst and lvl > 0]


def _fmt_duration(seconds: float) -> str:
    seconds = round(seconds)
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{seconds // 60} min"
    return f"{seconds // 3600} h {seconds % 3600 // 60} min"


def _fmt_mbps(mbps: float) -> str:
    return f"{mbps / 1000:.2f} Gbps" if mbps >= 1000 else f"{mbps:.1f} Mbps" if mbps < 10 else f"{mbps:.0f} Mbps"


def make_icon_image(color: tuple[int, int, int], size: int = 64) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    pad = size // 16
    draw.ellipse((pad, pad, size - pad, size - pad), fill=color + (255,), outline=(30, 30, 30, 255), width=max(1, size // 32))
    # Highlight to give a sphere effect
    hl = size // 4
    draw.ellipse((hl, hl, hl + size // 4, hl + size // 5), fill=(255, 255, 255, 110))
    return img


# --- Application ------------------------------------------------------------


class PingTrayApp:
    def __init__(self):
        self.cfg, self.config_error = load_config()
        i18n.set_language(self.cfg["language"])
        self.pinger = WindowsPinger() if sys.platform == "win32" else SubprocessPinger()
        self.samples = SampleWindow()
        self.images = {state: make_icon_image(rgb) for state, rgb in COLORS.items()}
        self.state = "gray"
        self.reasons: list[str] = []
        self.stats = Stats(0, 0, None, None, None, 0.0)
        self.stop_event = threading.Event()
        self._refresh_lock = threading.Lock()  # _refresh runs from the monitor and menu threads
        self.lan_node: lan.LanNode | None = None
        self.ping_peer: lan.Peer | None = None  # set by "Ping this peer": overrides the target
        self.peer_results: dict[str, str] = {}  # peer id -> last speed test result
        self.testing: set[str] = set()  # peer ids with a speed test running

        self.icon = pystray.Icon(
            APP_NAME,
            icon=self.images["gray"],
            title=t("waiting_title", app=APP_NAME),
            menu=pystray.Menu(
                # default=True: also runs on left-click of the tray icon
                pystray.MenuItem(f"{APP_NAME} v{__version__}", self._show_version, default=True),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(lambda _: self._status_line(), None, enabled=False),
                pystray.MenuItem(lambda _: self._loss_line(), None, enabled=False),
                pystray.MenuItem(lambda _: self._history_loss_line(), None, enabled=False),
                pystray.MenuItem(lambda _: self._outages_line(), None, enabled=False),
                pystray.MenuItem(lambda _: self._rtt_line(), None, enabled=False),
                pystray.MenuItem(
                    lambda _: self._config_error_line(), None, enabled=False,
                    visible=lambda _: bool(self.config_error),
                ),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(
                    lambda _: t("menu_lan_peers"), pystray.Menu(self._peer_items),
                    visible=lambda _: self.cfg["lan_enabled"],
                ),
                pystray.MenuItem(lambda _: t("menu_open_settings"), self._open_config),
                pystray.MenuItem(lambda _: t("menu_reload_settings"), self._reload_config),
                pystray.MenuItem(lambda _: t("menu_quit"), self._quit),
            ),
        )

    # Menu / tooltip text

    def _target(self) -> str:
        return self.ping_peer.addr if self.ping_peer else self.cfg["target"]

    def _status_line(self, with_reasons: bool = True) -> str:
        if not self._target():
            return t("no_target")
        name = t("lan_target", name=self.ping_peer.name) if self.ping_peer else self.cfg["target"]
        line = f"{name}: {t(f'state_{self.state}')}"
        if with_reasons and self.reasons:
            line += f" ({', '.join(t(f'metric_{r}') for r in self.reasons)})"
        return line

    def _config_error_line(self) -> str:
        return t("config_error", error=i18n.error_text(self.config_error)) if self.config_error else ""

    def _loss_line(self) -> str:
        s = self.stats
        return t("loss_window", pct=s.loss_pct, lost=s.lost, sent=s.sent, minutes=self.cfg["window_minutes"])

    def _history_loss_line(self) -> str:
        s = self.stats
        return t("loss_hour", pct=s.history_loss_pct, lost=s.history_lost, sent=s.history_sent)

    def _outages_line(self) -> str:
        s = self.stats
        if s.outage_ongoing:
            return t("outage_ongoing", duration=_fmt_duration(s.last_outage_s), count=s.outages)
        if not s.outages:
            return t("outages_none")
        return t(
            "outages_line", count=s.outages,
            ago=_fmt_duration(s.last_outage_ago_s), duration=_fmt_duration(s.last_outage_s),
        )

    def _rtt_line(self, with_last: bool = True) -> str:
        s = self.stats
        avg = f"{s.avg_rtt:.0f} ms" if s.avg_rtt is not None else "-"
        jitter = f"{s.jitter:.0f} ms" if s.jitter is not None else "-"
        line = t("latency_line", avg=avg, jitter=jitter)
        if with_last:
            last = f"{s.last_rtt:.0f} ms" if s.last_rtt is not None else t("lost")
            line += " · " + t("last_rtt", value=last)
        return line

    def _tooltip(self) -> str:
        # Windows caps the tooltip at 127 characters: use the most detailed version that fits,
        # dropping first the reasons, then the hourly loss, then the outages
        s = self.stats
        hour = f" · {t('loss_hour_short', pct=s.history_loss_pct)}"
        if s.outage_ongoing:
            outages = " · " + t("outage_short_ongoing", duration=_fmt_duration(s.last_outage_s))
        elif s.outages:
            outages = " · " + t("outages_short", count=s.outages)
        else:
            outages = ""
        rtt = self._rtt_line(with_last=False)
        candidates = [
            (True, hour, outages), (False, hour, outages), (False, "", outages), (False, "", ""),
        ]
        for with_reasons, hour_part, outages_part in candidates:
            tooltip = f"{self._status_line(with_reasons)}\n{self._loss_line()}{hour_part}\n{rtt}{outages_part}"
            if len(tooltip) <= 127:
                return tooltip
        return tooltip[:127]

    def _peer_items(self):
        node = self.lan_node
        if node is None:
            yield pystray.MenuItem(t("lan_not_started"), None, enabled=False)
            return
        if node.error:
            yield pystray.MenuItem(t("lan_disabled", error=node.error), None, enabled=False)
            return
        yield pystray.MenuItem(t("this_pc", name=node.name), None, enabled=False)
        peers = node.peers()
        if not peers:
            yield pystray.MenuItem(t("no_peers"), None, enabled=False)
        for peer in peers:
            yield pystray.MenuItem(f"{peer.name} ({peer.addr})", pystray.Menu(*self._peer_actions(peer)))

    def _peer_actions(self, peer: lan.Peer) -> list[pystray.MenuItem]:
        testing = peer.id in self.testing
        status = t("testing") if testing else self.peer_results.get(peer.id)
        items = [pystray.MenuItem(status, None, enabled=False)] if status else []
        return items + [
            pystray.MenuItem(
                t("run_speed_test"), lambda icon, item: self._start_speed_test(peer), enabled=not testing,
            ),
            pystray.MenuItem(
                t("ping_peer"), lambda icon, item: self._toggle_ping_peer(peer),
                checked=lambda _: self.ping_peer is not None and self.ping_peer.id == peer.id,
            ),
        ]

    # Menu actions

    def _show_version(self, icon, item):
        try:
            icon.notify(
                f"{self._status_line()}\n{self._loss_line()}\n{self._history_loss_line()}\n"
                f"{self._outages_line()}\n{self._rtt_line()}",
                f"{APP_NAME} v{__version__}",
            )
        except Exception:
            pass  # some backends don't support notifications

    def _open_config(self, icon, item):
        if sys.platform == "win32":
            os.startfile(CONFIG_PATH)
        else:
            subprocess.Popen(["xdg-open", str(CONFIG_PATH)])

    def _reload_config(self, icon, item):
        old_cfg, old_target = self.cfg, self._target()
        self.cfg, self.config_error = load_config(self.cfg)
        i18n.set_language(self.cfg["language"])
        if any(self.cfg[key] != old_cfg[key] for key in LAN_KEYS):
            self._restart_lan()
        if self._target() != old_target:
            self.samples.clear()
        self._refresh()

    # LAN

    def _restart_lan(self):
        if self.lan_node is not None:
            self.lan_node.stop()
            self.lan_node = None
        if not self.cfg["lan_enabled"]:
            self.ping_peer = None
            return
        cfg = self.cfg
        self.lan_node = lan.LanNode(cfg["lan_name"], cfg["lan_port"], cfg["lan_secret"], __version__)
        self.lan_node.start()

    def _toggle_ping_peer(self, peer: lan.Peer):
        same = self.ping_peer is not None and self.ping_peer.id == peer.id
        self.ping_peer = None if same else peer
        self.samples.clear()
        self._refresh()

    def _start_speed_test(self, peer: lan.Peer):
        if peer.id in self.testing:
            return
        self.testing.add(peer.id)
        self.icon.update_menu()
        threading.Thread(target=self._speed_test_worker, args=(peer,), daemon=True).start()

    def _speed_test_worker(self, peer: lan.Peer):
        cfg = self.cfg
        try:
            # Own pinger: the monitor thread's one isn't safe to share
            pinger = WindowsPinger() if sys.platform == "win32" else SubprocessPinger()
            try:
                rtts = [pinger.ping(peer.addr, cfg["timeout_ms"]) for _ in range(SPEEDTEST_PINGS)]
            finally:
                pinger.close()
            result = lan.speed_test(peer, cfg["speedtest_seconds"], cfg["lan_secret"])
            ok = [r for r in rtts if r is not None]
            avg = sum(ok) / len(ok) if ok else None
            latency = t("ping_lost") if avg is None else "<1 ms" if avg < 1 else f"{avg:.0f} ms"
            text = f"↓ {_fmt_mbps(result.down_mbps)} · ↑ {_fmt_mbps(result.up_mbps)} · {latency}"
        except lan.RefusedError as e:
            key = f"refused_{e.code}"
            text = t("test_failed", error=t(key) if i18n.has(key) else str(e))
        except Exception as e:  # report any failure instead of leaving the peer stuck in "Testing…"
            text = t("test_failed", error=e)
        self.peer_results[peer.id] = text
        self.testing.discard(peer.id)
        try:
            self.icon.notify(text, t("speed_test_title", name=peer.name))
        except Exception:
            pass  # some backends don't support notifications
        self.icon.update_menu()

    def _quit(self, icon, item):
        self.stop_event.set()
        icon.stop()

    # Monitoring loop

    def _refresh(self):
        with self._refresh_lock:
            cfg = self.cfg
            self.stats = self.samples.stats(cfg["window_minutes"] * 60, cfg["outage_min_lost"])
            new_state, self.reasons = classify(self.stats, cfg)
            if new_state != self.state:
                old_state, self.state = self.state, new_state
                self.icon.icon = self.images[new_state]
                # Skip the expected gray -> green at startup, but report problems found then
                if cfg["notify_on_change"] and not (old_state == "gray" and new_state == "green"):
                    try:
                        self.icon.notify(
                            f"{self._loss_line()}\n{self._history_loss_line()}\n"
                            f"{self._outages_line()}\n{self._rtt_line()}",
                            self._status_line(),
                        )
                    except Exception:
                        pass  # some backends don't support notifications
            self.icon.title = self._tooltip()
            self.icon.update_menu()

    def _monitor_loop(self):
        next_run = time.monotonic()
        while not self.stop_event.is_set():
            cfg = self.cfg
            try:
                target = self._target()
                if target:  # idle until a target is set and settings are reloaded
                    self.samples.add(self.pinger.ping(target, cfg["timeout_ms"]))
                self._refresh()
            except Exception:
                # Keep monitoring: if this thread died the icon would freeze on its last color
                traceback.print_exc()
            next_run += cfg["interval_seconds"]
            delay = next_run - time.monotonic()
            if delay < 0:  # the ping took longer than the interval
                next_run = time.monotonic()
                delay = 0
            self.stop_event.wait(delay)

    def _setup(self, icon):
        icon.visible = True
        self._restart_lan()
        threading.Thread(target=self._monitor_loop, daemon=True).start()

    def run(self):
        try:
            self.icon.run(setup=self._setup)
        finally:
            self.stop_event.set()
            if self.lan_node is not None:
                self.lan_node.stop()
            self.pinger.close()


if __name__ == "__main__":
    PingTrayApp().run()
