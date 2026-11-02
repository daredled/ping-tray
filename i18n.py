"""User-facing strings in each supported language, and detection of the OS language.

To add a language, add a dict to STRINGS under its ISO 639-1 code with the same keys as "en".
A key missing from a language falls back to the English text.
"""

import ctypes
import locale
import os
import sys

FALLBACK = "en"

STRINGS = {
    "en": {
        "state_green": "Stable connection",
        "state_yellow": "Unstable connection",
        "state_red": "Connection problems",
        "state_gray": "Waiting for data",
        "metric_loss": "loss",
        "metric_latency": "latency",
        "metric_jitter": "jitter",
        "waiting_title": "{app}: waiting for data",
        "no_target": "No target set in config.json",
        "lan_target": "{name} (LAN)",
        "loss_window": "Loss: {pct:.2f}% ({lost}/{sent}) in {minutes:g} min",
        "loss_hour": "Loss: {pct:.2f}% ({lost}/{sent}) in the last hour",
        "loss_hour_short": "1 h: {pct:.2f}%",
        "outages_none": "Outages in the last hour: none",
        "outages_line": "Outages in the last hour: {count} · last: {ago} ago, lasted {duration}",
        "outage_ongoing": "Outage in progress: {duration} ({count} in the last hour)",
        "outages_short": "outages 1 h: {count}",
        "outage_short_ongoing": "OUTAGE {duration}",
        "latency_line": "Latency: {avg} · jitter: {jitter}",
        "last_rtt": "last: {value}",
        "lost": "lost",
        "menu_lan_peers": "LAN peers",
        "menu_open_settings": "Open settings",
        "menu_reload_settings": "Reload settings",
        "menu_quit": "Quit",
        "lan_not_started": "LAN not started",
        "lan_disabled": "LAN disabled: {error}",
        "this_pc": "This PC: {name}",
        "no_peers": "No peers found yet",
        "testing": "Testing…",
        "run_speed_test": "Run speed test",
        "ping_peer": "Ping this peer",
        "speed_test_title": "Speed test: {name}",
        "ping_lost": "ping lost",
        "test_failed": "Test failed: {error}",
        "refused_secret": "the peer uses a different lan_secret",
        "refused_busy": "the peer is busy with another test",
        "refused_bad_request": "the peer rejected the request (different version?)",
        "config_error": "config.json error: {error}",
        "cfg_target": 'set "target" to the host to ping',
        "cfg_positive": "interval_seconds, window_minutes and timeout_ms must be > 0",
        "cfg_thresholds": "{green} cannot be greater than {yellow}",
        "cfg_lan_port": "lan_port must be between 1 and 65535",
        "cfg_speedtest": "speedtest_seconds must be > 0 and <= {max}",
        "cfg_outage_min_lost": "outage_min_lost must be >= 1",
    },
    "es": {
        "state_green": "Conexión estable",
        "state_yellow": "Conexión inestable",
        "state_red": "Problemas de conexión",
        "state_gray": "Esperando datos",
        "metric_loss": "pérdida",
        "metric_latency": "latencia",
        "metric_jitter": "jitter",
        "waiting_title": "{app}: esperando datos",
        "no_target": "Falta configurar target en config.json",
        "lan_target": "{name} (LAN)",
        "loss_window": "Pérdida: {pct:.2f}% ({lost}/{sent}) en {minutes:g} min",
        "loss_hour": "Pérdida: {pct:.2f}% ({lost}/{sent}) en la última hora",
        "loss_hour_short": "1 h: {pct:.2f}%",
        "outages_none": "Cortes en la última hora: ninguno",
        "outages_line": "Cortes en la última hora: {count} · último: hace {ago}, duró {duration}",
        "outage_ongoing": "Corte en curso: {duration} ({count} en la última hora)",
        "outages_short": "cortes 1 h: {count}",
        "outage_short_ongoing": "CORTE {duration}",
        "latency_line": "Latencia: {avg} · jitter: {jitter}",
        "last_rtt": "último: {value}",
        "lost": "perdido",
        "menu_lan_peers": "Equipos en la LAN",
        "menu_open_settings": "Abrir configuración",
        "menu_reload_settings": "Recargar configuración",
        "menu_quit": "Salir",
        "lan_not_started": "LAN no iniciada",
        "lan_disabled": "LAN desactivada: {error}",
        "this_pc": "Este PC: {name}",
        "no_peers": "Aún no se encontraron equipos",
        "testing": "Probando…",
        "run_speed_test": "Correr test de velocidad",
        "ping_peer": "Hacer ping a este equipo",
        "speed_test_title": "Test de velocidad: {name}",
        "ping_lost": "ping perdido",
        "test_failed": "El test falló: {error}",
        "refused_secret": "el otro equipo usa otro lan_secret",
        "refused_busy": "el otro equipo está ocupado con otro test",
        "refused_bad_request": "el otro equipo rechazó la solicitud (¿otra versión?)",
        "config_error": "Error en config.json: {error}",
        "cfg_target": 'configura "target" con el host al que hacer ping',
        "cfg_positive": "interval_seconds, window_minutes y timeout_ms deben ser > 0",
        "cfg_thresholds": "{green} no puede ser mayor que {yellow}",
        "cfg_lan_port": "lan_port debe estar entre 1 y 65535",
        "cfg_speedtest": "speedtest_seconds debe ser > 0 y <= {max}",
        "cfg_outage_min_lost": "outage_min_lost debe ser >= 1",
    },
}

_language = FALLBACK


class LocalizedError(ValueError):
    """An error whose message is translated when shown, so it follows later language changes."""

    def __init__(self, key: str, **kwargs):
        super().__init__(STRINGS[FALLBACK][key].format(**kwargs))
        self.key = key
        self.kwargs = kwargs


def os_language() -> str:
    """ISO 639-1 code of the OS display language (e.g. "es"), or "" if it can't be determined."""
    name = ""
    if sys.platform == "win32":
        try:
            langid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
            # Unknown sublanguage (e.g. a new regional variant): try the primary language
            name = locale.windows_locale.get(langid) or locale.windows_locale.get(0x400 | (langid & 0x3FF), "")
        except (AttributeError, OSError):
            pass
    else:
        for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
            if os.environ.get(var):
                name = os.environ[var]
                break
    return name.split(":")[0].split(".")[0].split("_")[0].split("-")[0].lower()


def set_language(code: str = "") -> str:
    """Selects the language (the OS one if code is empty), falling back to English. Returns it."""
    global _language
    code = (code or os_language()).lower()
    _language = code if code in STRINGS else FALLBACK
    return _language


def t(key: str, **kwargs) -> str:
    text = STRINGS[_language].get(key) or STRINGS[FALLBACK][key]
    return text.format(**kwargs) if kwargs else text


def has(key: str) -> bool:
    return key in STRINGS[FALLBACK]


def error_text(e: BaseException) -> str:
    return t(e.key, **e.kwargs) if isinstance(e, LocalizedError) else str(e)
