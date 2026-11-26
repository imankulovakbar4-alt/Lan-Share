#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LAN Share — быстрая передача файлов между ПК в локальной сети.

TCP (при возможности — внутри TLS) — передача файлов, UDP broadcast — обнаружение.
Все сетевые операции — в отдельных потоках, GUI не блокируется.

Структура файла (блочная, чтобы блок можно было удалить/переписать отдельно):

  ЧАСТЬ 1. ЛОГИКА И СЕТЬ (работает без окон, общается с GUI через self._ui())
    1.1  Настройки: чтение/запись конфига
    1.1a Шифрование TLS, история передач, избранные машины
    1.2  Запуск сети: слушатели, handshake
    1.3  Обнаружение машин в сети (UDP broadcast), поиск по коду
    1.4  Приём подключений и файлов (TCP: резюме, SHA-256, режимы приёма)
    1.5  Комната: создание, остановка, вход по коду
    1.6  Отправка файлов, прогресс и отмена
    1.7  Администратор: кик и бан (бан сохраняется между запусками)
    1.8  Мост в интерфейс (потокобезопасная очередь)
    1.9  Чат и буфер обмена между участниками комнаты

  ЧАСТЬ 2. ГРАФИЧЕСКИЙ ИНТЕРФЕЙС (каждый блок защищён проверкой hasattr —
  удаление блока деградирует одну функцию, но не ломает программу)
    2.1  Сборка интерфейса: шапка, страницы, стили, виджеты (подблоки 2.1.0–2.1.15)
    2.2  Вход в комнату: двойной клик, код, ручной адрес IP:порт
    2.3  Файлы: drag-and-drop, проводник, список отправки
    2.4  Чекбоксы получателей, меню участника и избранное
    2.5  Обновление интерфейса (только главный поток)
    2.6  Журнал событий
    2.7  Настройки: папка загрузок, режим приёма, SHA-256
    2.8  Закрытие программы
    2.9  История передач

Протокол: версия 2 (TLS-шифрование, докачка через .part, SHA-256, чат).
Версии программы на обоих ПК должны совпадать.
Шифрование отключается переменной окружения LAN_SHARE_NO_TLS=1.

Интерфейс адаптивный: страницы «Обмен» и «Настройки» прокручиваются, «Обмен» сам переключается
между одной и двумя колонками, шапка перестраивается, панель прогресса закреплена внизу.

Оформление: две темы (тёмная/светлая, переключатель в шапке, класс C), ttk-тема clam —
            сторонние темы (sv-ttk) больше не нужны.

Зависимости:  pip install tkinterdnd2   (необязательно, нужно для drag-and-drop)
              pip install cryptography   (нужно для TLS; без него — без шифрования)
Запуск:       python lan_share.py
"""

import json
import os
import queue
import secrets
import socket
import ssl
import threading
import time
import uuid

from core.protocol import read_json_header, validate_file_header
from storage.paths import CERT_DIR, CONFIG_PATH, HISTORY_PATH, prepare_storage
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter import font as tkfont

try:
    from tkinterdnd2 import COPY, DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False

UDP_PORT = 51313          # фиксированный порт UDP для обнаружения
TCP_PORT = 51314          # предпочтительный TCP-порт (нужен для «избранных»)
CHUNK = 256 * 1024        # размер куска при передаче файла
PEER_TTL = 12             # секунд до удаления "протухшей" машины из списка
ANNOUNCE_PERIOD = 3       # период рассылки о себе, сек
PROTO_VER = 2             # версия протокола передачи (TLS, резюме, SHA-256, чат)
CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"   # без похожих 0/O, 1/I/L
CODE_LEN = 6              # длина кода комнаты
MAX_JOIN_FAILS = 5        # попыток ввода кода до временной блокировки IP
JOIN_BLOCK_SEC = 600      # длительность блокировки IP, сек
HISTORY_LIMIT = 500       # сколько записей истории хранить
INBOX_MAX = 40            # всего ожидающих запросов в панели «Входящие»
INBOX_PER_SENDER = 5      # ожидающих запросов от одного отправителя
INBOX_TTL = 85            # сек до авто-отказа по запросу на файл (раньше 90 с у принимающего потока)
INBOX_TEXT_TTL = 600      # сек хранения присланного текста в панели
MUTE_SEC = 600            # на сколько игнорируем отправителя, сек
POLL_BATCH = 150          # событий интерфейса за один такт (окно не зависает при потоке)
ROOM_EMPTY = "· · · · · ·"   # заглушка вместо кода, пока комнаты нет


# Настройки пользователя (меняются на странице «Настройки», хранятся в конфиге).
# Значения по умолчанию = прежние константы; диапазоны ограничивают неверный ввод.
DEFAULT_OPTS = {
    "device_name": "",            # пусто — имя компьютера
    "font_size": 10,              # базовый размер шрифта интерфейса
    "sound": True,                # звук при уведомлениях
    "default_access": "public",   # доступ к новой комнате: public | code
    "autostart": False,           # создавать комнату при запуске программы
    "trust_favs": False,          # файлы от «избранных» (★) ПК принимаются без вопросов
    "subfolders": False,          # раскладывать принятые файлы по папкам отправителей
    "on_conflict": "rename",      # файл уже есть: rename | overwrite
    "auto_limit_mb": 0,           # автоприём только до N МБ (0 — без ограничения)
    "tcp_port": TCP_PORT,         # предпочтительный TCP-порт (нужен перезапуск)
    "announce_period": ANNOUNCE_PERIOD,
    "peer_ttl": PEER_TTL,
    "inbox_ttl": INBOX_TTL,       # сек до авто-отказа по запросу на файл
    "mute_min": MUTE_SEC // 60,   # на сколько минут игнорируем отправителя
    "max_fails": MAX_JOIN_FAILS,  # неверных кодов до блокировки IP
    "block_min": JOIN_BLOCK_SEC // 60,
}
OPT_RANGE = {
    "font_size": (8, 16), "auto_limit_mb": (0, 1000000), "tcp_port": (1024, 65535),
    "announce_period": (1, 60), "peer_ttl": (5, 300), "inbox_ttl": (10, 600),
    "mute_min": (1, 1440), "max_fails": (1, 50), "block_min": (1, 1440),
}
OPT_CHOICES = {"default_access": ("public", "code"), "on_conflict": ("rename", "overwrite")}


class C:
    """Палитра оформления. Две темы: тёмная и светлая (монохром + один акцент для статусов).
    Все цвета интерфейса берутся отсюда; C.apply("light") переключает тему."""
    THEMES = {
        "dark": dict(
            BG="#09090b", SURFACE="#111113", SURFACE2="#18181b",
            ROW_A="#111113", ROW_B="#151518",
            HOVER="#232326", HOVER2="#2f2f34",
            BORDER="#222226", BORDER2="#33333a", SEL="#27272c",
            TEXT="#fafafa", MUTED="#a1a1aa", FAINT="#5a5a63",
            ACCENT="#fafafa", ACCENT_HI="#ffffff", INFO="#60a5fa",
            PRIMARY="#fafafa", PRIMARY_HI="#e4e4e7", PRIMARY_LO="#d4d4d8",
            PRIMARY_DIS="#27272a", ON_PRIMARY="#09090b",
            OK="#4ade80", WARN="#fbbf24",
            DANGER="#ef4444", DANGER_HI="#f87171", DANGER_LO="#dc2626",
            DANGER_DIS="#3b1d1d", DROP_HOT="#1c1c20"),
        "light": dict(
            BG="#f4f4f5", SURFACE="#ffffff", SURFACE2="#f4f4f5",
            ROW_A="#ffffff", ROW_B="#fafafa",
            HOVER="#e4e4e7", HOVER2="#d4d4d8",
            BORDER="#e4e4e7", BORDER2="#d4d4d8", SEL="#e4e4e7",
            TEXT="#09090b", MUTED="#71717a", FAINT="#a1a1aa",
            ACCENT="#09090b", ACCENT_HI="#27272a", INFO="#2563eb",
            PRIMARY="#18181b", PRIMARY_HI="#3f3f46", PRIMARY_LO="#09090b",
            PRIMARY_DIS="#d4d4d8", ON_PRIMARY="#fafafa",
            OK="#16a34a", WARN="#b45309",
            DANGER="#dc2626", DANGER_HI="#b91c1c", DANGER_LO="#b91c1c",
            DANGER_DIS="#fecaca", DROP_HOT="#ececee"),
    }

    @classmethod
    def apply(cls, name):
        for key, val in cls.THEMES.get(name, cls.THEMES["dark"]).items():
            setattr(cls, key, val)


C.apply("dark")


def lan_ip():
    """Собственный IP в локальной сети (или 127.0.0.1, если сети нет)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _enable_dpi_awareness():
    """Windows: включить DPI-осведомлённость до создания окна (иначе текст мыльный)."""
    if os.name != "nt":
        return
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def hostname():
    return (socket.gethostname() or "PC").split(".")[0]


def unique_path(folder, name):
    """Путь для сохранения: не перезаписывает существующие файлы."""
    base, ext = os.path.splitext(name)
    candidate = os.path.join(folder, name)
    n = 1
    while os.path.exists(candidate):
        candidate = os.path.join(folder, f"{base} ({n}){ext}")
        n += 1
    return candidate


class ScrollFrame(ttk.Frame):
    """Прокручиваемый контейнер. Содержимое (self.inner) всегда занимает всю ширину окна
    и, если окно выше содержимого, растягивается по высоте; если не помещается —
    появляется вертикальная прокрутка (колесо мыши работает над любым местом страницы)."""

    def __init__(self, parent, bg, step=24):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0,
                                yscrollincrement=step)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = ttk.Frame(self.canvas)
        self._win = self.canvas.create_window(0, 0, window=self.inner, anchor="nw")
        self._shown = False
        self._last = (0, 0, 0)
        self.canvas.bind("<Configure>", self._fit, add="+")
        self.inner.bind("<Configure>", self._fit, add="+")
        self.after(250, self._tick)

    def _tick(self):
        """Содержимое могло вырасти/уменьшиться без события Configure (скрытая панель и т.п.)."""
        try:
            if not self.winfo_exists():
                return
            self._fit()
            self.after(250, self._tick)
        except tk.TclError:
            pass

    def _fit(self, _e=None):
        try:
            cw, ch = self.canvas.winfo_width(), self.canvas.winfo_height()
            if cw < 2 or ch < 2:
                return
            req = self.inner.winfo_reqheight()
            key = (cw, ch, req)
            if key == self._last:
                return
            self._last = key
            h = max(req, ch)
            self.canvas.itemconfigure(self._win, width=cw, height=h)
            self.canvas.configure(scrollregion=(0, 0, cw, h))
            need = req > ch
            if need != self._shown:
                self._shown = need
                if need:
                    self.vsb.pack(side="right", fill="y")
                else:
                    self.vsb.pack_forget()
                    self.canvas.yview_moveto(0)
        except tk.TclError:
            pass

    def needs_scroll(self):
        return self._shown


class App:

    # ===========================================================================
    # СБОРКА: состояние сессии + создание интерфейса
    # ===========================================================================
    def __init__(self):
        prepare_storage()  # create user-data folders and migrate legacy files
        _enable_dpi_awareness()          # чёткий текст на Windows с масштабом 125–200 %
        self.root = TkinterDnD.Tk() if HAS_DND else tk.Tk()
        self._k = max(1.0, self.root.winfo_fpixels("1i") / 96.0)   # масштаб экрана
        self.root.title("LAN Share — обмен файлами в локальной сети")
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self._init_w = min(self.px(1020), max(self.px(520), sw - self.px(60)))
        ih = min(self.px(840), max(self.px(460), sh - self.px(120)))
        self.root.geometry(f"{self._init_w}x{ih}+{max((sw - self._init_w) // 2, 0)}"
                           f"+{max((sh - ih) // 3, 0)}")
        self.root.minsize(self.px(520), self.px(440))

        # --- состояние ---
        self.my_id = uuid.uuid4().hex[:12]
        self.my_ip = lan_ip()
        self.room = None                 # код комнаты (после «Запустить сервер»)
        self.peers = {}                  # найденные машины: id -> info
        self.members = {}                # подключённые участники: id -> info
        self.roster = {}                 # участники комнаты, полученные от админа (для гостей)
        self.banned = {}                 # баны: ip -> {"host", "id"} (сохраняются в конфиг)
        self.favorites = {}              # избранные машины: ip -> {"host", "ip", "port"}
        self.is_admin = False            # админ = тот, кто создал комнату
        self.room_access = "public"      # доступ: "public" | "code"
        self.member_vars = {}            # id -> tk.BooleanVar (чекбоксы получателей)
        self.pending_files = []          # подготовленные к отправке файлы
        self.sending = False
        self._send_jobs = 0
        self.pending_code = None         # код комнаты, которую сейчас ищем по сети
        self.ui = queue.Queue()          # очередь событий для GUI
        self.lock = threading.RLock()
        # Limit concurrent inbound sockets so connection floods cannot spawn unbounded threads.
        self._connection_slots = threading.BoundedSemaphore(32)
        self.transfers = {}              # id -> активная передача (прогресс и отмена)
        self._tid = 0
        self.failed_joins = {}           # ip -> {"count", "until"} — защита от перебора кода
        self._ctl_lock = threading.Lock()  # запись в контрольные сокеты участников
        self._tree_rows = {}             # iid строки дерева -> info
        self._hist_rows = []             # записи истории в порядке отображения
        self._toast_job = None
        self._log_buf = []               # последние записи журнала (для пересборки UI)
        self._cur_page = "send"
        self.inbox = {}                  # ожидающие запросы: iid -> {kind, host, ...}
        self._inbox_id = 0
        self._inbox_tick = 0.0
        self.muted = {}                  # игнор отправителей: имя -> до какого времени
        self._spam_cnt = {}              # имя -> сколько запросов отклонено автоматически
        self._spam_log = {}              # имя -> когда последний раз писали об этом в журнал
        self._last_bell = 0.0

        self.totals = {"in": 0, "out": 0}
        self.cfg = self._load_config()
        self.opts = self._load_opts(self.cfg.get("opts"))
        self.theme = self.cfg.get("theme", "dark")
        if self.theme not in C.THEMES:
            self.theme = "dark"
        C.apply(self.theme)
        home_dl = os.path.join(os.path.expanduser("~"), "Downloads")
        stored = self.cfg.get("download_dir") or ""
        if not stored or os.path.normcase(stored) == os.path.normcase(home_dl):
            stored = os.path.join(home_dl, "LAN-Share")   # не смешиваем с обычными загрузками
        self.download_dir = stored

        self.receive_mode = self.cfg.get("receive_mode", "ask")
        if self.receive_mode not in ("auto", "ask", "reject"):
            self.receive_mode = "ask"
        self.verify_hash = bool(self.cfg.get("verify_hash", True))
        for f in self.cfg.get("favorites", []) or []:
            ip = str(f.get("ip") or "")
            if ip and f.get("port"):
                self.favorites[ip] = {"host": f.get("host") or ip, "ip": ip,
                                      "port": int(f["port"])}
        for b in self.cfg.get("bans", []) or []:
            ip = str(b.get("ip") or "")
            if ip:
                self.banned[ip] = {"host": b.get("host") or "", "id": b.get("id") or ""}
        self.history = self._load_history()

        self.visible = tk.BooleanVar(value=self.cfg.get("visible", True))
        self.visible_flag = bool(self.cfg.get("visible", True))

        # TCP-порт для данных (слушаем сразу, чтобы уметь и отдавать, и принимать).
        # Сначала пробуем фиксированный порт — тогда «избранные» работают между запусками.
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.tcp_sock.bind(("", self.opts["tcp_port"]))
        except OSError:
            self.tcp_sock.bind(("", 0))
        self.tcp_port = self.tcp_sock.getsockname()[1]
        self.tcp_sock.listen(16)

        # UDP-сокет для обнаружения: биндим сразу, до запуска потоков
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 0)
        except (AttributeError, OSError):
            pass
        self.udp_sock.bind(("", UDP_PORT))
        self.udp_sock.settimeout(1.0)

        # TLS: самоподписанный сертификат, если доступен cryptography
        self.ssl_srv, self.ssl_cli = self._setup_tls()

        self._build_ui()
        self._start_threads()
        self._poll_id = self.root.after(100, self._poll_ui)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        if self.opts["autostart"]:
            self.root.after(400, self._start_server)

    # ===========================================================================
    # ЧАСТЬ 1. ЛОГИКА И СЕТЬ
    # Работает без кнопок и окон; с интерфейсом общается через self._ui().
    # Каждый блок можно переписать или отключить отдельно от остальных.
    # ===========================================================================

    # --- Блок 1.1. Настройки: чтение и запись файла конфигурации ---------

    def _load_config(self):
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_config(self):
        self.visible_flag = bool(self.visible.get())
        self.cfg = {
            "download_dir": self.download_dir,
            "visible": self.visible_flag,
            "receive_mode": self.receive_mode,
            "verify_hash": self.verify_hash,
            "theme": self.theme,
            "opts": dict(self.opts),
            "favorites": list(self.favorites.values()),
            "bans": [{"host": v.get("host", ""), "ip": ip, "id": v.get("id", "")}
                     for ip, v in self.banned.items()],
        }
        try:
            tmp = CONFIG_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.cfg, f, ensure_ascii=False, indent=2)
            os.replace(tmp, CONFIG_PATH)
        except OSError:
            pass

    @staticmethod
    def _clean_opt(key, val):
        """Привести значение настройки к нужному типу и диапазону (или вернуть None)."""
        default = DEFAULT_OPTS[key]
        try:
            if isinstance(default, bool):
                return bool(val)
            if isinstance(default, int):
                lo, hi = OPT_RANGE.get(key, (0, 10 ** 9))
                return max(lo, min(hi, int(str(val).strip())))
            val = str(val).strip()
            if key in OPT_CHOICES:
                return val if val in OPT_CHOICES[key] else None
            return val[:32]
        except (TypeError, ValueError):
            return None

    def _load_opts(self, raw):
        opts = dict(DEFAULT_OPTS)
        if isinstance(raw, dict):
            for key in DEFAULT_OPTS:
                if key in raw:
                    val = self._clean_opt(key, raw[key])
                    if val is not None:
                        opts[key] = val
        return opts

    def my_name(self):
        """Имя этого ПК в сети: своё из настроек или имя компьютера."""
        return self.opts["device_name"] or hostname()

    # --- Блок 1.1a. TLS, история, коды комнат, форматирование ------------

    def _setup_tls(self):
        """Серверный и клиентский SSL-контексты. None — если шифрование недоступно."""
        if os.environ.get("LAN_SHARE_NO_TLS"):
            self._log("Шифрование отключено переменной LAN_SHARE_NO_TLS")
            return None, None
        cert = os.path.join(CERT_DIR, "cert.pem")
        key = os.path.join(CERT_DIR, "key.pem")
        if not (os.path.exists(cert) and os.path.exists(key)):
            if not self._make_cert(cert, key):
                self._log("TLS недоступен: нет пакета cryptography — трафик без шифрования")
                return None, None
        try:
            srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            srv.load_cert_chain(cert, key)
            cli = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            cli.check_hostname = False
            cli.verify_mode = ssl.CERT_NONE
            return srv, cli
        except (ssl.SSLError, OSError) as e:
            self._log(f"Не удалось включить TLS ({e}) — трафик без шифрования")
            return None, None

    def _make_cert(self, cert_path, key_path):
        """Самоподписанный сертификат локальной сети (через cryptography)."""
        try:
            import datetime as _dt
            import ipaddress
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
        except ImportError:
            return False
        try:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LAN Share")])
            now = _dt.datetime.now(_dt.timezone.utc)
            crt = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - _dt.timedelta(days=1))
                   .not_valid_after(now + _dt.timedelta(days=3650))
                   .add_extension(x509.SubjectAlternativeName([
                       x509.DNSName("lan-share"),
                       x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                   .sign(key, hashes.SHA256()))
            os.makedirs(CERT_DIR, exist_ok=True)
            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()))
            with open(cert_path, "wb") as f:
                f.write(crt.public_bytes(serialization.Encoding.PEM))
            return True
        except Exception as e:
            self._log(f"Не удалось создать сертификат TLS: {e}")
            return False

    @staticmethod
    def _norm_code(text):
        """Код комнаты: без пробелов и в верхнем регистре (ввод в любом регистре)."""
        return "".join(str(text or "").split()).upper()

    @staticmethod
    def _gen_code():
        return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LEN))

    @staticmethod
    def _sha256(path):
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _fmt_size(n):
        n = float(n or 0)
        for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
            if n < 1024 or unit == "ТБ":
                return f"{int(n)} Б" if unit == "Б" else f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} ТБ"

    @staticmethod
    def _fmt_eta(sec):
        if sec is None or sec != sec or sec <= 0 or sec > 86400 * 7:
            return "—"
        sec = int(sec)
        if sec < 60:
            return f"{sec} с"
        return f"{sec // 60}:{sec % 60:02d}"

    def _load_history(self):
        try:
            with open(HISTORY_PATH, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _add_history(self, direction, name, peer, path, size, status="ok"):
        rec = {"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
               "dir": direction, "name": name, "peer": peer or "",
               "path": path or "", "size": int(size or 0), "status": status}
        with self.lock:            # запись файла тоже под замком — историю пишут потоки передач
            self.history.append(rec)
            del self.history[:-HISTORY_LIMIT]
            try:
                tmp = HISTORY_PATH + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self.history, f, ensure_ascii=False)
                os.replace(tmp, HISTORY_PATH)
            except OSError:
                pass
        self._ui("history")

    # --- Блок 1.2. Запуск сети: слушатели, handshake ----------------------

    def _start_threads(self):
        self.alive = True
        threading.Thread(target=self._announce, daemon=True).start()
        threading.Thread(target=self._udp_listener, daemon=True).start()
        threading.Thread(target=self._tcp_accept_loop, daemon=True).start()

    def _my_hello(self, join_code=None):
        return {"type": "hello", "id": self.my_id, "host": self.my_name(),
                "ip": self.my_ip, "port": self.tcp_port, "room": self.room or "",
                "access": self.room_access if self.room else "",
                "admin": self.is_admin, "ver": PROTO_VER,
                "join_code": join_code or ""}

    # --- Блок 1.3. Обнаружение машин в сети (UDP broadcast) ---------------

    def _announce_pkt(self, hidden=False):
        """Пакет о себе. Код закрытой комнаты наружу не отдаём — только по запросу с кодом."""
        room = ""
        if self.is_admin and self.room and self.room_access == "public":
            room = self.room
        return {"id": self.my_id, "host": self.my_name(), "ip": self.my_ip,
                "port": self.tcp_port, "room": room, "ver": PROTO_VER,
                "access": self.room_access if (self.is_admin and self.room) else "",
                "hidden": hidden, "visible": True}

    def _announce(self):
        """Раз в несколько секунд рассылаем информацию о себе по UDP broadcast."""
        while self.alive:
            with self.lock:
                self._prune_peers()
                visible = self.visible_flag
                pkt = self._announce_pkt()
                admin = self.is_admin
            if visible and admin:      # announce только хозяин комнаты; гости себя не светят
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    s.sendto(json.dumps(pkt).encode("utf-8"), ("<broadcast>", UDP_PORT))
                    s.close()
                except OSError as e:
                    self._ui("log", f"Ошибка рассылки: {e}")
            time.sleep(self.opts["announce_period"])

    def _udp_listener(self):
        """Слушаем UDP-объявления других машин."""
        s = self.udp_sock
        while self.alive:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                p = json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(p, dict):
                continue
            if p.get("type") == "query":
                self._answer_query(p, addr)
                continue
            pid = p.get("id")
            if not pid or not isinstance(pid, str):
                continue          # чужой или битый пакет — поток не должен падать
            if pid == self.my_id or not p.get("visible", True):
                continue  # себя не показываем и «невидимок» не добавляем
            try:
                port = int(p.get("port") or 0)
            except (TypeError, ValueError):
                continue
            with self.lock:
                self.peers[pid] = {
                    "id": pid, "host": str(p.get("host") or addr[0])[:64],
                    "ip": addr[0], "port": port,
                    "room": p.get("room", ""), "access": p.get("access", ""),
                    "hidden": bool(p.get("hidden")), "seen": time.time(),
                }
            self._ui("peers")
            self._maybe_join_pending(p)

    def _answer_query(self, pkt, addr):
        """Ответ на поиск по коду: работает и для «невидимок» — только если код верный."""
        if not (self.room and self.is_admin):
            return
        if self._norm_code(pkt.get("code")) != self.room:
            return
        try:
            pkt = self._announce_pkt(hidden=True)
            pkt["room"] = self.room      # спрашивающий уже знает код — подтверждаем комнату
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(json.dumps(pkt).encode("utf-8"), addr)
            s.close()
        except OSError:
            pass

    def _maybe_join_pending(self, p):
        code = self.pending_code
        if not code or p.get("room") != code:
            return
        self.pending_code = None
        with self.lock:
            peer = dict(self.peers.get(p["id"]) or {})
        if peer:
            peer["join_code"] = code
            threading.Thread(target=self._connect_peer, args=(peer,), daemon=True).start()

    def _prune_peers(self):
        now = time.time()
        for pid in [k for k, v in self.peers.items() if now - v["seen"] > self.opts["peer_ttl"]]:
            del self.peers[pid]
            self._ui("peers")

    # --- Блок 1.4. Приём подключений и файлов (TCP) -----------------------

    def _tcp_accept_loop(self):
        while self.alive:
            try:
                conn, addr = self.tcp_sock.accept()
            except OSError:
                break
            if not self._connection_slots.acquire(blocking=False):
                self._reject(conn, "Слишком много одновременных подключений. Повторите позже.")
                continue
            try:
                threading.Thread(target=self._handle_conn_guarded,
                                 args=(conn, addr), daemon=True).start()
            except RuntimeError:
                self._connection_slots.release()
                self._reject(conn, "Не удалось запустить обработчик подключения.")

    def _handle_conn_guarded(self, conn, addr):
        try:
            self._handle_conn(conn, addr)
        finally:
            self._connection_slots.release()

    @staticmethod
    def _reject(conn, reason):
        """Отправить отказ и закрыть соединение."""
        try:
            conn.sendall((json.dumps({"type": "reject", "reason": reason}) + "\n")
                         .encode("utf-8"))
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass

    def _handle_conn(self, conn, addr):
        try:
            conn.settimeout(15)
            if self.ssl_srv:
                # Рукопожатие — в рабочем потоке, чтобы не блокировать accept-цикл
                conn = self.ssl_srv.wrap_socket(conn, server_side=True)
            rf = conn.makefile("rb")
            header = read_json_header(rf)
            if header.get("type") == "file":
                try:
                    validate_file_header(header)
                except ValueError as exc:
                    self._reject(conn, f"Некорректный запрос файла: {exc}")
                    return
            if header.get("type") == "hello":
                blocked = self.failed_joins.get(addr[0])
                if blocked and blocked.get("until", 0) > time.time():
                    left = max(1, int((blocked["until"] - time.time()) // 60) + 1)
                    self._reject(conn, f"Слишком много неверных попыток. Повторите через {left} мин.")
                    self._log(f"Заблокирован вход с {addr[0]}: перебор кода комнаты")
                    return
                banned_ids = {v.get("id") for v in self.banned.values()}
                if addr[0] in self.banned or header.get("id") in banned_ids:
                    reason = "Вы забанены администратором этой комнаты"
                    self._reject(conn, reason)
                    self._log(f"Забаненный пытался подключиться — отклонён: "
                              f"{header.get('host')} ({addr[0]})")
                    return
                if not (self.room and self.is_admin):
                    self._reject(conn, "На этом ПК нет активной комнаты")
                    self._log(f"Отклонено прямое подключение по IP:порт: {addr[0]}")
                    return
                if header.get("room") and header["room"] != self.room:
                    self._reject(conn, "Этот ПК уже в другой комнате")
                    self._log(f"Отклонён вход из другой комнаты: {header.get('host')}")
                    return
                if int(header.get("ver") or 1) < PROTO_VER:
                    self._log(f"Внимание: {header.get('host')} использует старую версию — "
                              f"файлы и чат могут не работать")
                err = self._check_join(header, addr[0])
                if err:
                    self._reject(conn, err)
                    self._log(f"Отклонён (неверный вход): {header.get('host')} ({addr[0]})")
                    return
                self.failed_joins.pop(addr[0], None)
                conn.settimeout(None)          # контрольный сокет без таймаута — иначе участники «вылетают»
                self._register_member(header, conn, rf=rf)
            elif header.get("type") == "file":
                if addr[0] in self.banned:
                    self._reject(conn, "Вы забанены администратором этой комнаты")
                    return
                self._recv_file(conn, rf, header)
            else:
                conn.close()
        except Exception as e:
            self._log(f"Ошибка соединения с {addr[0]}: {e}")
            try:
                conn.close()
            except OSError:
                pass

    def _check_join(self, hello, ip):
        """Проверка входа в комнату. Возвращает текст ошибки или None."""
        if self.room_access == "code":
            if self._norm_code(hello.get("join_code")) != self.room:
                with self.lock:
                    st = self.failed_joins.setdefault(ip, {"count": 0, "until": 0})
                    st["count"] += 1
                    if st["count"] >= self.opts["max_fails"]:
                        st["count"] = 0
                        st["until"] = time.time() + self.opts["block_min"] * 60
                        self._log(f"IP {ip} заблокирован на {self.opts['block_min']} мин "
                                  f"за перебор кода комнаты")
                return "Неверный код комнаты"
        return None

    def _register_member(self, hello, sock, send_reply=True,
                         join_code=None, rf=None):
        mid = hello.get("id") or uuid.uuid4().hex[:8]
        room = hello.get("room", "")
        with self.lock:
            member = {
                "id": mid,
                "host": hello.get("host") or "PC",
                "ip": hello.get("ip") or "0.0.0.0",
                "port": int(hello.get("port") or 0),
                "room": room or self.room or "",
                "ver": int(hello.get("ver") or 1),
                "sock": sock,
                "rf": rf,
            }
            old = self.members.get(mid)
            if old:
                try:
                    old["sock"].close()
                except OSError:
                    pass
            self.members[mid] = member
        # отвечаем своим hello (только сторона, принимавшая подключение)
        if send_reply:
            try:
                sock.sendall((json.dumps(self._my_hello(join_code)) + "\n").encode("utf-8"))
            except OSError:
                pass
        self._ui("members")
        self._log(f"Подключился участник: {member['host']} ({member['ip']})")
        threading.Thread(target=self._member_reader, args=(member,), daemon=True).start()
        self._send_roster()

    def _send_roster(self):
        """Админ рассылает участникам список всех, чтобы гости видели друг друга."""
        if not self.is_admin:
            return
        with self.lock:
            peers = [{"id": m["id"], "host": m["host"], "ip": m["ip"],
                      "port": m["port"]} for m in self.members.values()]
            socks = [m["sock"] for m in self.members.values()]
        msg = (json.dumps({"type": "roster", "members": peers}) + "\n").encode("utf-8")
        with self._ctl_lock:
            for s in socks:
                try:
                    s.sendall(msg)
                except OSError:
                    pass

    def _member_reader(self, member):
        """Живёт, пока открыт контрольный сокет участника; при разрыве убирает его."""
        rf = member.get("rf")
        if rf is None:
            try:
                rf = member["sock"].makefile("rb")
            except OSError:
                rf = None
        try:
            while rf is not None and self.alive:
                line = rf.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                mtype = msg.get("type")
                if mtype == "kick":
                    self._log(f"{self.my_name()}: администратор исключил вас из комнаты")
                    break
                elif mtype == "ban":
                    self._log(f"{self.my_name()}: администратор забанил вас (бан сохраняется)")
                    break
                elif mtype == "reject":
                    self._log(f"Отказ в подключении: {msg.get('reason', 'без причины')}")
                    break
                elif mtype == "chat":
                    text = str(msg.get("text") or "")
                    if msg.get("kind") == "clipboard":
                        self._ui("clipboard", member["host"], text)
                        self._log(f"Чат · {member['host']} прислал текст в буфер обмена "
                                  f"({len(text)} симв.)")
                    else:
                        flat = text.replace("\r", " ").replace("\n", " / ")
                        self._log(f"Чат · {member['host']}: {flat[:500]}")
                elif mtype == "roster":
                    with self.lock:
                        self.roster = {m["id"]: {"id": m["id"], "host": m.get("host", "PC"),
                                                 "ip": m.get("ip", ""),
                                                 "port": int(m.get("port") or 0)}
                                       for m in msg.get("members", [])
                                       if m.get("id") != self.my_id}
                    self._ui("members")
                elif mtype == "hello":
                    with self.lock:
                        m = self.members.get(member["id"])
                        if m:
                            m["admin"] = bool(msg.get("admin"))
                            m["ver"] = int(msg.get("ver") or 1)
                            if msg.get("room"):
                                m["room"] = msg["room"]
                    if int(msg.get("ver") or 1) < PROTO_VER:
                        self._log(f"Внимание: {member['host']} использует старую версию — "
                                  f"файлы и чат могут не работать")
                    if msg.get("room") and not self.room and not self.is_admin:
                        self.room = msg["room"]
                        self.room_access = msg.get("access") or "public"
                        self._ui("room", self.room)
                        self._log(f"Вы вошли в комнату {self.room}")
                    self._ui("members")
        except OSError:
            pass
        with self.lock:
            if self.members.get(member["id"]) is member:
                del self.members[member["id"]]
            leave = (not self.is_admin and member.get("admin")
                     and self.room and member.get("room") == self.room)
            if leave:
                self.room = None
                self.room_access = "public"
                self.roster = {}
        try:
            member["sock"].close()
        except OSError:
            pass
        self._ui("members")
        self._send_roster()
        self._log(f"Участник отключился: {member['host']}")
        if leave:
            self._ui("room_off")
            self._log("Вы вышли из комнаты (хозяин отключился).")

    @staticmethod
    def _safe_rel(rel):
        """Безопасный относительный путь: без '..', дисков и абсолютных путей."""
        rel = (rel or "").replace("\\", "/")
        parts = [p for p in rel.split("/") if p not in ("", ".", "..") and ":" not in p]
        return "/".join(parts) or "file.bin"

    def _recv_file(self, conn, rf, header):
        try:
            size = validate_file_header(header)
        except ValueError as exc:
            self._reject(conn, f"Некорректный запрос файла: {exc}")
            return
        if int(header.get("ver") or 0) != PROTO_VER:
            self._reject(conn, "Версия протокола не совпадает — обновите LAN Share на обоих ПК")
            self._log("Отклонён файл от несовместимой версии программы")
            return
        name = os.path.basename(header.get("name", "file.bin"))
        rel = self._safe_rel(header.get("rel") or name)
        sender = header.get("sender", "?")
        digest = str(header.get("sha256") or "")
        sid = "".join(c for c in str(header.get("sender_id") or "") if c.isalnum())[:12] or "anon"

        mode = self.receive_mode
        try:
            peer_ip = conn.getpeername()[0]
        except (OSError, IndexError):
            peer_ip = ""
        if mode == "ask" and self.opts["trust_favs"] and peer_ip in self.favorites:
            mode = "auto"         # доверенный ПК из избранного
        limit = self.opts["auto_limit_mb"]
        if mode == "auto" and limit and size > limit * 1024 * 1024:
            mode = "ask"          # слишком большой файл — не принимаем молча
        if mode == "reject":
            self._reject(conn, "Получатель не принимает входящие файлы")
            self._log(f"Отклонён приём «{rel}» от {sender}: приём отключён в настройках")
            self._add_history("in", rel, sender, "", size, "reject")
            return
        if mode == "ask":
            decision = self._confirm_receive(rel, sender, size)
            if decision is not True:
                if decision is None:       # автоотказ при спаме: без журнала и истории
                    self._reject(conn, "Слишком много запросов, повторите позже")
                else:
                    self._reject(conn, "Получатель отказался принимать файл")
                    self._log(f"Вы отклонили приём «{rel}» от {sender}")
                    self._add_history("in", rel, sender, "", size, "reject")
                return

        parts = rel.split("/")
        base_dir = self.download_dir
        if self.opts["subfolders"]:
            who = "".join(c for c in str(sender) if c.isalnum() or c in " ._-").strip(" .")
            base_dir = os.path.join(base_dir, who[:40] or "anon")
        folder = os.path.join(base_dir, *parts[:-1])
        try:
            os.makedirs(folder, exist_ok=True)
        except OSError as e:
            self._reject(conn, "Не удалось создать папку для сохранения")
            self._log(f"Ошибка приёма «{rel}»: папка недоступна ({e})")
            return

        # Частичный файл: имя привязано к отправителю, чтобы повторный приём докачивался
        part = os.path.join(folder, f".{parts[-1]}.{sid}.part")
        offset = 0
        try:
            have = os.path.getsize(part)
            if have <= size:
                offset = have
            else:
                os.remove(part)
        except OSError:
            offset = 0
        try:
            conn.sendall((json.dumps({"type": "accept", "offset": offset}) + "\n").encode("utf-8"))
        except OSError:
            try:
                conn.close()
            except OSError:
                pass
            return

        conn.settimeout(120)
        tid, tr = self._new_transfer("in", f"{sender}: {parts[-1]}", size, offset, sender)
        got = offset
        self._log(f"Приём «{rel}» от {sender}: {self._fmt_size(size)}"
                  + (f", докачка с {self._fmt_size(offset)}" if offset else ""))
        try:
            with open(part, "ab" if offset else "wb") as f:
                while got < size:
                    if tr["cancel"].is_set():
                        raise ConnectionAbortedError("отменено пользователем")
                    chunk = rf.read(min(CHUNK, size - got))
                    if not chunk:
                        raise ConnectionError("соединение оборвалось")
                    f.write(chunk)
                    got += len(chunk)
                    self._update_transfer(tid, got, tr)
            if self.verify_hash and digest:
                if self._sha256(part) != digest:
                    try:
                        os.remove(part)
                    except OSError:
                        pass
                    conn.sendall(b"BAD\n")
                    self._log(f"Контрольная сумма не совпала: «{rel}» — файл удалён")
                    self._add_history("in", rel, sender, "", size, "error")
                    return
            if self.opts["on_conflict"] == "overwrite":
                dest = os.path.join(folder, parts[-1])
            else:
                dest = unique_path(folder, parts[-1])
            os.replace(part, dest)
            conn.sendall(b"OK\n")
            self._log(f"Принят файл «{rel}» от {sender}, сохранён: {dest}")
            self._add_history("in", rel, sender, dest, size, "ok")
            self._ui("toast", f"Принят: {parts[-1]}")
        except ConnectionAbortedError:
            self._log(f"Приём «{rel}» отменён; часть сохранена для докачки")
            self._add_history("in", rel, sender, part, got, "cancel")
        except Exception as e:
            self._log(f"Ошибка приёма файла «{rel}»: {e}")
            self._add_history("in", rel, sender,
                              part if os.path.exists(part) else "", got, "error")
        finally:
            self._finish_transfer(tid)
            try:
                conn.close()
            except OSError:
                pass

    # --- Блок 1.4a. Прогресс и отмена передач -----------------------------

    def _new_transfer(self, direction, name, size, base, peer):
        with self.lock:
            self._tid += 1
            tid = self._tid
            tr = {"id": tid, "dir": direction, "name": name,
                  "size": max(int(size or 0), 1), "sent": int(base or 0),
                  "base": int(base or 0), "t0": time.time(), "peer": peer,
                  "cancel": threading.Event(), "last_ui": 0.0}
            self.transfers[tid] = tr
        self._ui("progress", tid)
        return tid, tr

    def _update_transfer(self, tid, sent, tr=None):
        with self.lock:
            tr = tr or self.transfers.get(tid)
            if not tr:
                return
            tr["sent"] = sent
            now = time.time()
            if now - tr["last_ui"] < 0.08:    # не заваливаем главный поток событиями
                return
            tr["last_ui"] = now
        self._ui("progress", tid)

    def _finish_transfer(self, tid):
        with self.lock:
            tr = self.transfers.pop(tid, None)
            if tr:       # итоги за сеанс для нижней панели
                got = max(min(tr["sent"], tr["size"]) - tr["base"], 0)
                key = "in" if tr["dir"] == "in" else "out"
                self.totals[key] += got
        self._ui("progress", -1)

    def _cancel_transfers(self):
        with self.lock:
            trs = list(self.transfers.values())
            for tr in trs:
                tr["cancel"].set()
        if trs:
            self._log(f"Отмена передач: {len(trs)}")
        if hasattr(self, "btn_cancel"):
            self.btn_cancel.config(state="disabled")

    def _confirm_receive(self, name, sender, size):
        """Запрос в панель «Входящие». True — принять, False — отказ, None — тихий автоотказ."""
        ev = threading.Event()
        box = {}
        self._ui("ask_file", name, sender, size, ev, box)
        if not ev.wait(self.opts["inbox_ttl"] + 5):
            return False
        ok = box.get("ok")
        return None if ok is None else bool(ok)

    # --- Блок 1.5. Комната: создание, остановка, вход по коду -------------

    def _toggle_server(self):
        if self.room:                    # админ — закрыть комнату, гость — выйти из неё
            self._stop_server()
        else:
            self._start_server()

    def _start_server(self):
        access = "code" if (hasattr(self, "cmb_access")
                            and self.cmb_access.get().startswith("только")) else "public"
        self.room = self._gen_code()
        self.room_access = access
        self.is_admin = True
        if hasattr(self, "lbl_admin"):
            self.lbl_admin.config(text="Вы администратор")
        if hasattr(self, "_show_room"):
            self._show_room(self.room)
        mode = "только по коду" if access == "code" else "публичный"
        self._log(f"Сервер запущен. Комната {self.room}, доступ: {mode}. Вы администратор.")

    def _stop_server(self):
        with self.lock:
            for m in list(self.members.values()):
                try:
                    m["sock"].close()
                except OSError:
                    pass
            self.members.clear()
            self.roster = {}
        was_admin = self.is_admin
        self.pending_code = None
        self.room = None
        self.is_admin = False
        self.room_access = "public"
        if hasattr(self, "lbl_admin"):
            self.lbl_admin.config(text="")
        if hasattr(self, "_show_room"):
            self._show_room(None)
        self._ui("members")
        self._log("Сервер остановлен. Комната закрыта, участники отключены."
                  if was_admin else "Вы вышли из комнаты.")

    def _connect_peer(self, peer):
        raw = None
        try:
            raw = socket.create_connection((peer["ip"], peer["port"]), timeout=10)
            sock = self.ssl_cli.wrap_socket(raw, server_hostname="lan-share") \
                if self.ssl_cli else raw
            sock.settimeout(None)
            sock.sendall((json.dumps(self._my_hello(peer.get("join_code"))) + "\n").encode("utf-8"))
            self._register_member(peer, sock, send_reply=False)
        except Exception as e:
            self._log(f"Не удалось подключиться к {peer.get('host')} ({peer.get('ip')}): {e}")
            try:
                if raw is not None:
                    raw.close()
            except OSError:
                pass

    def _join_by_code(self):
        """Войти по коду: сначала ищем в списке, потом спрашиваем сеть (работает и для «невидимок»)."""
        code = self._norm_code(self.ent_code.get())
        if not code:
            self._on_connect()
            return
        peer = None
        with self.lock:
            for p in self.peers.values():
                if p.get("room") == code:
                    peer = dict(p)
                    break
        if peer:
            peer["join_code"] = code
            threading.Thread(target=self._connect_peer, args=(peer,), daemon=True).start()
            return
        self.pending_code = code
        self._log(f"Ищем комнату {code} в сети…")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(json.dumps({"type": "query", "code": code,
                                 "id": self.my_id}).encode("utf-8"),
                     ("<broadcast>", UDP_PORT))
            s.close()
        except OSError as e:
            self.pending_code = None
            self._log(f"Не удалось отправить запрос: {e}")
            return

        def timeout():
            time.sleep(2.5)
            if self.pending_code == code:
                self.pending_code = None
                self._log(f"Комната {code} не найдена или код неверный.")

        threading.Thread(target=timeout, daemon=True).start()

    # --- Блок 1.6. Отправка файлов ----------------------------------------

    def _selected_targets(self):
        """Выбранные чекбоксами получатели (участники и участники из ростера)."""
        targets = [mid for mid, var in self.member_vars.items() if var.get()]
        with self.lock:
            chosen = []
            for mid in targets:
                if mid in self.members:
                    chosen.append(dict(self.members[mid]))
                elif mid in self.roster:
                    chosen.append(dict(self.roster[mid]))
        return chosen

    def _send_files(self):
        if self.sending:
            return
        if not self.pending_files:
            self._set_toast("Сначала добавьте файлы (перетащите или выберите)", sound=False, warn=True)
            return
        members = self._selected_targets()
        if not members:
            self._set_toast("Отметьте галочками получателей", sound=False, warn=True)
            return
        self.sending = True
        with self.lock:
            self._send_jobs = len(members)
        if hasattr(self, "btn_send"):
            self.btn_send.config(state="disabled")
        files = list(self.pending_files)
        for m in members:
            threading.Thread(target=self._send_to_member, args=(dict(m), files),
                             daemon=True).start()

    def _send_to_member(self, member, files):
        for item in files:
            if isinstance(item, (tuple, list)):
                path, rel = item
            else:
                path, rel = item, os.path.basename(item)
            name = os.path.basename(path)
            try:
                size = os.path.getsize(path)
            except OSError as e:
                self._log(f"Файл недоступен «{path}»: {e}")
                continue
            self._log(f"Отправка «{rel}» ({self._fmt_size(size)}), получатель: {member['host']}")
            try:
                self._send_one_file(member, path, rel, name, size)
            except Exception as e:      # на всякий случай: кнопка «Отправить» не должна зависать
                self._log(f"Ошибка отправки «{name}» на {member['host']}: {e}")
        with self.lock:
            self._send_jobs -= 1
            done = self._send_jobs <= 0
            if done:
                self.sending = False
        if done:
            self._ui("enable_send")

    def _send_one_file(self, member, path, rel, name, size):
        """Один файл одним соединением: заголовок, accept(offset), данные, OK/BAD."""
        tid = None
        raw = None
        try:
            digest = self._sha256(path) if self.verify_hash else ""
            raw = socket.create_connection((member["ip"], member["port"]), timeout=10)
            s = raw
            if self.ssl_cli:
                s = self.ssl_cli.wrap_socket(raw, server_hostname="lan-share")
            s.settimeout(120)       # большой файл по медленной сети не должен обрываться
            rf = s.makefile("rb")
            header = {"type": "file", "ver": PROTO_VER, "name": name, "rel": rel,
                      "size": size, "sha256": digest, "sender": self.my_name(),
                      "sender_id": self.my_id}
            s.sendall((json.dumps(header) + "\n").encode("utf-8"))
            line = rf.readline()
            reply = json.loads(line.decode("utf-8")) if line else {}
            if reply.get("type") != "accept":
                reason = reply.get("reason") or "получатель не принял файл"
                self._log(f"{member['host']}: {reason} — «{rel}» не отправлен")
                self._add_history("out", rel, member["host"], path, size, "reject")
                return
            offset = max(0, min(int(reply.get("offset") or 0), size))
            tid, tr = self._new_transfer("out", f"{member['host']}: {rel}", size, offset, member["host"])
            sent = offset
            with open(path, "rb") as f:
                f.seek(offset)
                while True:
                    if tr["cancel"].is_set():
                        raise ConnectionAbortedError("отменено пользователем")
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    s.sendall(chunk)
                    sent += len(chunk)
                    self._update_transfer(tid, sent, tr)
            ack = rf.readline().strip()
            if ack.startswith(b"OK"):
                self._log(f"«{name}» доставлен: {member['host']}")
                self._add_history("out", rel, member["host"], path, size, "ok")
            else:
                self._log(f"{member['host']} не подтвердил приём «{name}» "
                          f"(возможно, не сошлась контрольная сумма)")
                self._add_history("out", rel, member["host"], path, size, "error")
        except ConnectionAbortedError:
            self._log(f"Отправка «{name}» на {member['host']} отменена")
            self._add_history("out", rel, member["host"], path, size, "cancel")
        except Exception as e:
            self._log(f"Ошибка отправки «{name}» на {member['host']}: {e}")
            self._add_history("out", rel, member["host"], path, size, "error")
        finally:
            if tid is not None:
                self._finish_transfer(tid)
            try:
                if raw is not None:
                    raw.close()
            except OSError:
                pass

    # --- Блок 1.7. Администратор: кик и бан -------------------------------

    def _kick_member(self, mid):
        with self.lock:
            m = self.members.get(mid)
        if not m:
            return
        with self._ctl_lock:
            try:
                m["sock"].sendall(b'{"type": "kick"}\n')
            except OSError:
                pass
        try:
            m["sock"].close()
        except OSError:
            pass
        with self.lock:
            if self.members.get(mid) is m:
                del self.members[mid]
        self._ui("members")
        self._send_roster()
        self._log(f"Участник исключён из комнаты: {m['host']}")

    def _ban_member(self, mid):
        with self.lock:
            m = self.members.get(mid)
        if not m:
            return
        with self.lock:
            self.banned[m["ip"]] = {"host": m["host"], "id": mid}
        self._save_config()
        with self._ctl_lock:
            try:
                m["sock"].sendall(b'{"type": "ban"}\n')
            except OSError:
                pass
        try:
            m["sock"].close()
        except OSError:
            pass
        with self.lock:
            if self.members.get(mid) is m:
                del self.members[mid]
        self._ui("members")
        self._ui("bans")
        self._send_roster()
        self._log(f"Участник забанен (сохраняется между запусками): {m['host']} ({m['ip']})")

    def _unban_selected(self):
        sel = self.ban_list.curselection()
        if not sel:
            self._set_toast("Выберите участника в списке бана", sound=False, warn=True)
            return
        with self.lock:
            items = sorted(self.banned.items(),
                           key=lambda kv: (kv[1].get("host") or kv[0]).lower())
            if sel[0] >= len(items):
                return
            ip, info = items[sel[0]]
            self.banned.pop(ip, None)
        self._save_config()
        self._ui("bans")
        self._log(f'Разбанен: {info.get("host") or ip} ({ip})')

    # --- Блок 1.8. Мост в интерфейс (потокобезопасная очередь) ------------

    def _ui(self, kind, *args):
        self.ui.put((kind, args))

    # ===========================================================================
    # ЧАСТЬ 2. ГРАФИЧЕСКИЙ ИНТЕРФЕЙС
    # Все методы ниже трогают только виджеты. Каждый блок защищён проверкой
    # hasattr, поэтому удаление блока интерфейса не ломает остальные функции.
    # ===========================================================================

    # --- Блок 2.1. Сборка интерфейса: шапка, страницы, стили, виджеты -----

    def px(self, n):
        """Размер в пикселях с учётом масштаба экрана (DPI)."""
        return int(round(n * self._k))

    @staticmethod
    def _round_pts(x1, y1, x2, y2, r):
        """Точки скруглённого прямоугольника для create_polygon(smooth=True)."""
        return [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
                x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
                x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]

    @staticmethod
    def _plural(n, one, few, many):
        n = abs(int(n))
        if 11 <= n % 100 <= 14:
            return many
        return one if n % 10 == 1 else few if 2 <= n % 10 <= 4 else many

    # --- 2.1.0. Шрифты и стили -------------------------------------------

    def _init_fonts(self):
        fams = set(tkfont.families(self.root))

        def pick(*names):
            for n in names:
                if n in fams:
                    return n
            return None

        ui = pick("Segoe UI", "SF Pro Text", "Helvetica Neue", "Ubuntu",
                  "Noto Sans", "DejaVu Sans")
        mono = pick("Cascadia Mono", "Consolas", "Menlo", "DejaVu Sans Mono",
                    "Courier New")
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont",
                     "TkHeadingFont", "TkCaptionFont", "TkTooltipFont"):
            try:
                f = tkfont.nametofont(name)
                f.configure(size=self.opts["font_size"])
                if ui:
                    f.configure(family=ui)
            except tk.TclError:
                pass
        ui = ui or "TkDefaultFont"
        mono = mono or "TkFixedFont"
        b = self.opts["font_size"]
        self.F = {
            "ui": (ui, b), "small": (ui, b - 1), "bold": (ui, b, "bold"),
            "title": (ui, b + 6, "bold"), "big": (ui, b + 2, "bold"),
            "code": (mono, b + 12, "bold"), "mono": (mono, b + 1), "log": (mono, b - 1),
        }

    def _setup_style(self):
        F, px = self.F, self.px
        st = ttk.Style(self.root)
        st.theme_use("clam")
        self.root.configure(bg=C.BG)

        # выпадающие списки и контекстные меню (не ttk — настраиваются через option db)
        for pat, val in (
                ("*TCombobox*Listbox.background", C.SURFACE2),
                ("*TCombobox*Listbox.foreground", C.TEXT),
                ("*TCombobox*Listbox.selectBackground", C.PRIMARY),
                ("*TCombobox*Listbox.selectForeground", C.ON_PRIMARY),
                ("*TCombobox*Listbox.borderWidth", 0),
                ("*Menu.background", C.SURFACE2), ("*Menu.foreground", C.TEXT),
                ("*Menu.activeBackground", C.PRIMARY),
                ("*Menu.activeForeground", C.ON_PRIMARY),
                ("*Menu.borderWidth", 0), ("*Menu.activeBorderWidth", 0)):
            self.root.option_add(pat, val, 80)

        st.configure(".", background=C.BG, foreground=C.TEXT,
                     fieldbackground=C.SURFACE2, bordercolor=C.BORDER,
                     lightcolor=C.BORDER, darkcolor=C.BORDER,
                     troughcolor=C.SURFACE2, focuscolor=C.BG, font=F["ui"],
                     selectbackground=C.SEL, selectforeground=C.TEXT)
        st.map(".", foreground=[("disabled", C.FAINT)])

        # --- рамки и подписи ---
        st.configure("TFrame", background=C.BG)
        st.configure("Card.TFrame", background=C.SURFACE)
        st.configure("TLabel", background=C.BG, foreground=C.TEXT)
        st.configure("Card.TLabel", background=C.SURFACE)
        st.configure("Muted.TLabel", foreground=C.MUTED, font=F["small"])
        st.configure("CardMuted.TLabel", background=C.SURFACE,
                     foreground=C.MUTED, font=F["small"])
        st.configure("CardHead.TLabel", background=C.SURFACE, font=F["bold"])
        st.configure("Title.TLabel", font=F["title"])
        st.configure("Ok.TLabel", foreground=C.OK, font=F["small"])
        st.configure("Warn.TLabel", foreground=C.WARN, font=F["small"])
        st.configure("CardOk.TLabel", background=C.SURFACE, foreground=C.OK,
                     font=F["small"])
        st.configure("CardWarn.TLabel", background=C.SURFACE, foreground=C.WARN,
                     font=F["small"])
        st.configure("TSeparator", background=C.BORDER)

        # --- кнопки ---
        def button(name, bg, hi, lo, fg, dis_bg, dis_fg, pad=(14, 7), font=None):
            opts = dict(background=bg, foreground=fg, bordercolor=bg,
                        lightcolor=bg, darkcolor=bg, borderwidth=1,
                        relief="flat", padding=pad, focusthickness=0,
                        focuscolor=bg)
            if font:
                opts["font"] = font
            st.configure(name, **opts)
            states = [("disabled", dis_bg), ("pressed", lo), ("active", hi)]
            st.map(name, background=states, bordercolor=states,
                   lightcolor=states, darkcolor=states,
                   foreground=[("disabled", dis_fg)])

        button("TButton", C.HOVER, C.HOVER2, C.SURFACE2, C.TEXT,
               C.SURFACE2, C.FAINT)
        button("Accent.TButton", C.PRIMARY, C.PRIMARY_HI, C.PRIMARY_LO,
               C.ON_PRIMARY, C.PRIMARY_DIS, C.FAINT, font=F["bold"])
        button("Stop.TButton", C.DANGER, C.DANGER_HI, C.DANGER_LO,
               "#ffffff", C.DANGER_DIS, C.FAINT, font=F["bold"])
        button("Mini.TButton", C.HOVER, C.HOVER2, C.SURFACE2, C.TEXT,
               C.SURFACE2, C.FAINT, pad=(10, 4), font=F["small"])
        button("Nav.TButton", C.BG, C.SURFACE, C.SURFACE, C.MUTED,
               C.BG, C.FAINT, pad=(16, 7))
        button("NavOn.TButton", C.HOVER, C.HOVER, C.HOVER, C.TEXT,
               C.HOVER, C.FAINT, pad=(16, 7), font=F["bold"])

        # --- флажки ---
        for name, bg in (("TCheckbutton", C.BG), ("Card.TCheckbutton", C.SURFACE)):
            st.configure(name, background=bg, foreground=C.TEXT,
                         indicatorbackground=C.SURFACE2,
                         indicatorforeground=C.ON_PRIMARY,
                         upperbordercolor=C.BORDER2, lowerbordercolor=C.BORDER2,
                         focuscolor=bg, padding=(2, 3))
            st.map(name, background=[("active", bg)],
                   indicatorbackground=[("selected", C.PRIMARY),
                                        ("pressed", C.HOVER)],
                   upperbordercolor=[("selected", C.PRIMARY)],
                   lowerbordercolor=[("selected", C.PRIMARY)],
                   foreground=[("disabled", C.FAINT)])

        # --- поля ввода ---
        st.configure("TEntry", fieldbackground=C.SURFACE2, foreground=C.TEXT,
                     insertcolor=C.TEXT, bordercolor=C.BORDER2,
                     lightcolor=C.BORDER2, darkcolor=C.BORDER2,
                     padding=(8, 6))
        focus = [("focus", C.ACCENT)]
        st.map("TEntry", bordercolor=focus, lightcolor=focus, darkcolor=focus)
        st.configure("TCombobox", fieldbackground=C.SURFACE2,
                     background=C.SURFACE2, foreground=C.TEXT,
                     arrowcolor=C.MUTED, bordercolor=C.BORDER2,
                     lightcolor=C.BORDER2, darkcolor=C.BORDER2,
                     padding=(8, 5), arrowsize=px(14))
        st.map("TCombobox",
               fieldbackground=[("readonly", C.SURFACE2)],
               foreground=[("readonly", C.TEXT)],
               selectbackground=[("readonly", C.SURFACE2)],
               selectforeground=[("readonly", C.TEXT)],
               background=[("active", C.HOVER), ("readonly", C.SURFACE2)],
               arrowcolor=[("active", C.TEXT)],
               bordercolor=focus, lightcolor=focus, darkcolor=focus)

        st.configure("TSpinbox", fieldbackground=C.SURFACE2, foreground=C.TEXT,
                     background=C.SURFACE2, arrowcolor=C.MUTED, insertcolor=C.TEXT,
                     bordercolor=C.BORDER2, lightcolor=C.BORDER2, darkcolor=C.BORDER2,
                     padding=(8, 5), arrowsize=px(14))
        st.map("TSpinbox", bordercolor=focus, lightcolor=focus, darkcolor=focus,
               background=[("active", C.HOVER)])

        # --- таблицы ---
        st.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        st.configure("Treeview", background=C.SURFACE, fieldbackground=C.SURFACE,
                     foreground=C.TEXT, rowheight=px(round(32 * self.opts["font_size"] / 10)), borderwidth=0,
                     relief="flat", font=F["ui"])
        st.map("Treeview", background=[("selected", C.SEL)],
               foreground=[("selected", C.TEXT)])
        st.configure("Treeview.Heading", background=C.SURFACE, foreground=C.MUTED,
                     font=F["small"], padding=(8, 6), relief="flat",
                     borderwidth=0)
        st.map("Treeview.Heading", background=[("active", C.SURFACE)],
               foreground=[("active", C.TEXT)])

        # --- тонкий скроллбар без стрелок ---
        st.layout("Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {
            "sticky": "ns", "children": [("Vertical.Scrollbar.thumb",
                                          {"expand": "1", "sticky": "nswe"})]})])
        st.configure("Vertical.TScrollbar", background=C.HOVER,
                     troughcolor=C.SURFACE, bordercolor=C.SURFACE,
                     lightcolor=C.HOVER, darkcolor=C.HOVER, relief="flat",
                     gripcount=0, arrowsize=px(10))
        st.map("Vertical.TScrollbar",
               background=[("active", C.HOVER2), ("pressed", C.HOVER2)],
               lightcolor=[("active", C.HOVER2)], darkcolor=[("active", C.HOVER2)])

    # --- 2.1.0a. Мелкие помощники виджетов -------------------------------

    def _card(self, parent, title=None, hint=None, pad=16):
        """Карточка: рамка + заголовок. Возвращает (внешний фрейм, внутренний)."""
        px = self.px
        outer = tk.Frame(parent, bg=C.SURFACE, highlightthickness=1,
                         highlightbackground=C.BORDER, highlightcolor=C.BORDER)
        if title:
            hdr = ttk.Frame(outer, style="Card.TFrame")
            hdr.pack(fill="x", padx=px(pad), pady=(px(11), 0))
            tl = ttk.Label(hdr, text=title, style="CardHead.TLabel")
            tl.pack(side="left")
            if hint:
                hl = ttk.Label(hdr, text=hint, style="CardMuted.TLabel")
                hl.pack(side="right")
                shown = [True]

                def fit_hint(e, tl=tl, hl=hl, shown=shown):
                    # подсказка прячется, если в узкой карточке не хватает места
                    need = tl.winfo_reqwidth() + hl.winfo_reqwidth() + px(2 * pad + 24)
                    want = e.width >= need
                    if want != shown[0]:
                        shown[0] = want
                        if want:
                            hl.pack(side="right")
                        else:
                            hl.pack_forget()
                outer.bind("<Configure>", fit_hint, add="+")
        inner = ttk.Frame(outer, style="Card.TFrame")
        inner.pack(fill="both", expand=True, padx=px(pad),
                   pady=(px(8) if title else px(pad - 2), px(pad - 2)))
        return outer, inner

    def _menu(self):
        return tk.Menu(self.root, tearoff=0, bg=C.SURFACE2, fg=C.TEXT,
                       activebackground=C.PRIMARY, activeforeground=C.ON_PRIMARY,
                       bd=0, relief="flat", activeborderwidth=0,
                       font=self.F["ui"])

    def _listbox(self, parent, height):
        """Список в тёмной теме со скроллбаром. Возвращает (рамка, Listbox)."""
        wrap = ttk.Frame(parent, style="Card.TFrame")
        lb = tk.Listbox(wrap, height=height, width=8, bg=C.SURFACE2, fg=C.TEXT,
                        selectbackground=C.SEL, selectforeground=C.TEXT,
                        activestyle="none", relief="flat", bd=0,
                        highlightthickness=0, font=self.F["ui"],
                        exportselection=False)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=lb.yview)
        lb.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")          # сначала полоса — её не «съест» узкое окно
        lb.pack(side="left", fill="both", expand=True)
        return wrap, lb

    def _tree(self, parent, columns, heads, height, selectmode="browse"):
        """Таблица с зеброй и скроллбаром. heads: колонка -> (заголовок, ширина, якорь)."""
        wrap = ttk.Frame(parent, style="Card.TFrame")
        tv = ttk.Treeview(wrap, columns=columns, show="headings", height=height,
                          selectmode=selectmode)
        for c in columns:
            title, width, anchor = heads[c]
            tv.heading(c, text=title, anchor=anchor)
            tv.column(c, width=self.px(width), minwidth=self.px(48),
                      anchor=anchor, stretch=True)
        tv.tag_configure("odd", background=C.ROW_A)
        tv.tag_configure("even", background=C.ROW_B)
        tv.tag_configure("bad", foreground=C.DANGER_HI)
        tv.tag_configure("dim", foreground=C.MUTED)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        tv.pack(side="left", fill="both", expand=True)
        return wrap, tv

    def _autowrap(self, label, container, margin=8):
        """Длинная подпись переносится по ширине контейнера, а не обрезается."""
        container.bind("<Configure>", lambda e: label.configure(
            wraplength=max(self.px(120), e.width - self.px(margin))), add="+")

    def _show_page(self, key):
        self._cur_page = key
        self._pages[key].tkraise()
        for k, b in self._nav.items():
            b.configure(style="NavOn.TButton" if k == key else "Nav.TButton")

    # --- 2.1.0b. Состояние шапки: код комнаты, статус, кнопка сервера -----

    def _set_status(self, text, color):
        if hasattr(self, "lbl_status"):
            self.lbl_dot.itemconfigure(self.dot_item, fill=color)
            self.lbl_status.config(text=text)

    def _style_server_btn(self, running, guest=False):
        if not hasattr(self, "btn_server"):
            return
        if running or guest:
            self._srv_col = (C.DANGER, C.DANGER_HI)
            self.btn_server.config(text="Выйти из комнаты" if guest else "Остановить сервер",
                                   bg=C.DANGER, fg="#ffffff",
                                   activebackground=C.DANGER_LO,
                                   activeforeground="#ffffff")
        else:
            self._srv_col = (C.PRIMARY, C.PRIMARY_HI)
            self.btn_server.config(text="Запустить сервер", bg=C.PRIMARY,
                                   fg=C.ON_PRIMARY, activebackground=C.PRIMARY_LO,
                                   activeforeground=C.ON_PRIMARY)

    def _show_room(self, code=None):
        """Показать код комнаты и статус в шапке (None — комнаты нет)."""
        if hasattr(self, "lbl_room"):
            if code:
                self.lbl_room.config(text=code, foreground=C.OK)
            else:
                self.lbl_room.config(text=ROOM_EMPTY, foreground=C.FAINT)
        if hasattr(self, "btn_copy"):
            self.btn_copy.config(state="normal" if code else "disabled")
        if code:
            self._set_status(("Ваша комната · " if self.is_admin else "В комнате · ")
                             + code, C.OK)
        else:
            self._set_status("Не в комнате", C.FAINT)
        self._style_server_btn(bool(code and self.is_admin),
                               guest=bool(code and not self.is_admin))

    def _copy_room(self):
        if not self.room:
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.room)
            self._set_toast("Код комнаты скопирован")
        except tk.TclError:
            pass

    # --- 2.1.0c. Зона перетаскивания --------------------------------------

    def _draw_drop(self, hot=None):
        if not hasattr(self, "drop"):
            return
        if hot is not None:
            self._drop_hot = hot
        c, px, F = self.drop, self.px, self.F
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if w < 40 or h < 20:
            return
        hot = self._drop_hot
        c.create_polygon(self._round_pts(2, 2, w - 2, h - 2, px(14)), smooth=True,
                         fill=C.DROP_HOT if hot else C.SURFACE2,
                         outline=C.ACCENT if hot else C.BORDER2, width=2,
                         dash=(6, 4))
        if HAS_DND:
            main, sub = "Перетащите файлы или папки сюда", "или нажмите, чтобы выбрать"
        else:
            main = "Нажмите, чтобы выбрать файлы"
            sub = "перетаскивание: pip install tkinterdnd2"
        c.create_text(w / 2, h / 2 - px(10), text=main, font=F["big"],
                      fill=C.TEXT if hot else C.TEXT)
        c.create_text(w / 2, h / 2 + px(13), text=sub, font=F["small"],
                      fill=C.ACCENT_HI if hot else C.MUTED)

    def _update_pending_info(self):
        if not hasattr(self, "lbl_files"):
            return
        n = len(self.pending_files)
        if not n:
            self.lbl_files.config(text="Файлы не выбраны")
            return
        total = 0
        for full, _rel in self.pending_files:
            try:
                total += os.path.getsize(full)
            except OSError:
                pass
        word = self._plural(n, "файл", "файла", "файлов")
        self.lbl_files.config(text=f"{n} {word} · {self._fmt_size(total)}")

    # --- 2.1.1. Основная сборка -------------------------------------------

    def _build_ui(self, first=True):
        self._init_fonts()
        self._setup_style()
        F, px = self.F, self.px
        gap = px(12)
        self._hdr_key = self._send_key = self._hist_key = None

        outer = self._outer = ttk.Frame(self.root)
        outer.pack(fill="both", expand=True, padx=px(14), pady=px(10))

        # --- 2.1.2. Шапка: логотип, навигация, статус (перестраивается по ширине) ---
        header = self._header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, px(10)))
        header.columnconfigure(1, weight=1)

        brand = self._brand = ttk.Frame(header)
        size = px(40)
        logo = tk.Canvas(brand, width=size, height=size, bg=C.BG,
                         highlightthickness=0)
        logo.pack(side="left")
        logo.create_polygon(self._round_pts(1, 1, size - 1, size - 1, px(11)),
                            smooth=True, fill=C.PRIMARY, outline="")
        for y, (xa, xb) in ((0.38, (0.27, 0.73)), (0.62, (0.73, 0.27))):
            logo.create_line(size * xa, size * y, size * xb, size * y,
                             fill=C.ON_PRIMARY, width=px(2), arrow="last",
                             arrowshape=(px(7), px(8), px(3)), capstyle="round")
        titles = ttk.Frame(brand)
        titles.pack(side="left", padx=(px(10), px(12)))
        ttk.Label(titles, text="LAN Share", style="Title.TLabel").pack(anchor="w")
        self.lbl_me = ttk.Label(
            titles, style="Muted.TLabel", justify="left",
            text=f"Этот ПК: {self.my_name()} · {self.my_ip} · порт {self.tcp_port}")
        self.lbl_me.pack(anchor="w")

        nav = self._navbar = ttk.Frame(header)

        right = self._hright = ttk.Frame(header)
        self.btn_theme = ttk.Button(
            right, style="Mini.TButton", command=self._toggle_theme,
            text="Светлая тема" if self.theme == "dark" else "Тёмная тема")
        self.btn_theme.pack(side="right", padx=(px(10), 0))
        pill = tk.Frame(right, bg=C.SURFACE2, highlightthickness=1,
                        highlightbackground=C.BORDER)
        pill.pack(side="right")
        d = px(9)
        self.lbl_dot = tk.Canvas(pill, width=d, height=d, bg=C.SURFACE2,
                                 highlightthickness=0)
        self.dot_item = self.lbl_dot.create_oval(0, 0, d - 1, d - 1,
                                                 fill=C.FAINT, outline="")
        self.lbl_dot.pack(side="left", padx=(px(12), px(6)), pady=px(8))
        self.lbl_status = tk.Label(pill, text="Не в комнате", bg=C.SURFACE2,
                                   fg=C.TEXT, font=F["small"])
        self.lbl_status.pack(side="left", padx=(0, px(13)))
        self.lbl_admin = ttk.Label(right, text="", style="Warn.TLabel")
        self.lbl_admin.pack(side="right", padx=(0, px(10)))

        # --- 2.1.2a. Нижняя панель: прогресс, скорость/ETA, отмена, подсказки.
        # Закреплена внизу окна на всех страницах и не прокручивается. ---
        pcard, pc = self._card(outer, pad=10)
        pcard.pack(side="bottom", fill="x", pady=(px(10), 0))
        pc.columnconfigure(0, weight=1)
        self.pbar_h = px(8)
        self.pbar = tk.Canvas(pc, width=10, height=self.pbar_h, bg=C.SURFACE, bd=0,
                              highlightthickness=0)
        self.pbar.grid(row=0, column=0, sticky="ew", pady=px(4))
        self.pbar_val = 0
        self.pbar_trough = self.pbar.create_line(
            0, 0, 0, 0, width=self.pbar_h, fill=C.SURFACE2, capstyle="round")
        self.pbar_fill = self.pbar.create_line(
            0, 0, 0, 0, width=self.pbar_h, fill=C.ACCENT, capstyle="round",
            state="hidden")
        self.pbar.bind("<Configure>", lambda e: self._draw_progress(self.pbar_val))
        self.btn_cancel = ttk.Button(pc, text="Отмена", style="Stop.TButton",
                                     command=self._cancel_transfers, state="disabled")
        self.btn_cancel.grid(row=0, column=1, padx=(px(10), 0))
        ttk.Button(pc, text="Папка загрузок", style="Mini.TButton",
                   command=self._open_downloads).grid(row=0, column=2, padx=(px(6), 0))
        self.lbl_prog = ttk.Label(pc, text="", style="CardMuted.TLabel",
                                  anchor="w", justify="left")
        self.lbl_prog.grid(row=1, column=0, columnspan=3, sticky="w", pady=(px(4), 0))
        self.lbl_toast = ttk.Label(pc, text="", style="CardOk.TLabel",
                                   anchor="w", justify="left")
        self.lbl_toast.grid(row=2, column=0, columnspan=3, sticky="w", pady=(px(4), 0))
        self.lbl_toast.grid_remove()
        self._autowrap(self.lbl_prog, pc, margin=24)
        self._autowrap(self.lbl_toast, pc, margin=24)

        # --- контейнер страниц (стопка фреймов, наверх поднимается нужный) ---
        stack = ttk.Frame(outer)
        stack.pack(fill="both", expand=True)
        stack.rowconfigure(0, weight=1)
        stack.columnconfigure(0, weight=1)
        self._pages, self._nav, self._scrolls = {}, {}, {}

        def add_page(key, label, scroll=False):
            if scroll:        # страница с прокруткой: содержимое — sf.inner
                sf = ScrollFrame(stack, C.BG, step=px(24))
                sf.grid(row=0, column=0, sticky="nsew")
                self._pages[key] = sf
                self._scrolls[key] = sf
                page = sf.inner
            else:
                page = ttk.Frame(stack)
                page.grid(row=0, column=0, sticky="nsew")
                self._pages[key] = page
            btn = ttk.Button(nav, text=label, style="Nav.TButton", takefocus=False,
                             command=lambda k=key: self._show_page(k))
            btn.pack(side="left", padx=(0, px(4)))
            self._nav[key] = btn
            return page

        # =====================================================================
        # Страница «Обмен» (одна колонка в узком окне, две — в широком)
        # =====================================================================
        tab = self._send_page = add_page("send", "Обмен", scroll=True)
        cards = self._send_cards = {}

        # --- 2.1.3. Карточка комнаты: сервер, код, доступ ---
        room_card, rc = self._card(tab, pad=14)
        cards["room"] = room_card
        self._rc = rc

        self.btn_server = tk.Button(rc, text="Запустить сервер",
                                    command=self._toggle_server,
                                    bg=C.PRIMARY, fg=C.ON_PRIMARY,
                                    activebackground=C.PRIMARY_LO,
                                    activeforeground=C.ON_PRIMARY, relief="flat",
                                    bd=0, padx=px(20), pady=px(11),
                                    font=F["bold"], cursor="hand2")
        self._srv_col = (C.PRIMARY, C.PRIMARY_HI)
        self.btn_server.bind(
            "<Enter>", lambda e: self.btn_server.config(bg=self._srv_col[1]))
        self.btn_server.bind(
            "<Leave>", lambda e: self.btn_server.config(bg=self._srv_col[0]))

        self._rc_sep = ttk.Separator(rc, orient="vertical")

        code_box = self._rc_code = ttk.Frame(rc, style="Card.TFrame")
        ttk.Label(code_box, text="Код комнаты", style="CardMuted.TLabel").pack(anchor="w")
        code_row = ttk.Frame(code_box, style="Card.TFrame")
        code_row.pack(anchor="w")
        self.lbl_room = ttk.Label(code_row, text=ROOM_EMPTY, style="Card.TLabel",
                                  font=F["code"], foreground=C.FAINT)
        self.lbl_room.pack(side="left")
        self.btn_copy = ttk.Button(code_row, text="Копировать", style="Mini.TButton",
                                   command=self._copy_room, state="disabled")
        self.btn_copy.pack(side="left", padx=(px(12), 0))

        acc_box = self._rc_acc = ttk.Frame(rc, style="Card.TFrame")
        ttk.Label(acc_box, text="Доступ к комнате", style="CardMuted.TLabel").pack(anchor="w")
        self.cmb_access = ttk.Combobox(acc_box, state="readonly", width=16,
                                       values=("публичная", "только по коду"))
        self.cmb_access.current(1 if self.opts["default_access"] == "code" else 0)
        self.cmb_access.pack(anchor="w", pady=(px(3), 0))

        # --- 2.1.4. Входящие запросы (скрыта, пока запросов нет) ---
        ib_card, ib = self._card(tab, pad=12)
        cards["inbox"] = ib_card
        self.inbox_card = ib_card
        ibtop = ttk.Frame(ib, style="Card.TFrame")
        ibtop.pack(fill="x")
        self.lbl_inbox = ttk.Label(ibtop, text="Входящие запросы", style="CardHead.TLabel")
        self.lbl_inbox.pack(side="left")
        ib_hint = ttk.Label(ib, style="CardMuted.TLabel", justify="left",
                            text=f"Файл без ответа отклоняется через {self.opts['inbox_ttl']} с. "
                                 f"Enter — принять, Delete — отклонить, Ctrl+A — выбрать все. "
                                 f"Для текста «Принять» копирует его в буфер обмена.")
        ib_hint.pack(side="bottom", anchor="w", pady=(px(6), 0))
        self._ib_hint = ib_hint
        self._autowrap(ib_hint, ib, margin=4)
        ibbtn = ttk.Frame(ib, style="Card.TFrame")
        ibbtn.pack(side="bottom", fill="x", pady=(px(8), 0))
        ibrow1 = ttk.Frame(ibbtn, style="Card.TFrame")
        ibrow1.pack(fill="x")
        ibrow2 = ttk.Frame(ibbtn, style="Card.TFrame")
        ibrow2.pack(fill="x", pady=(px(6), 0))
        self.btn_accept_all = ttk.Button(ibrow1, text="Принять все файлы",
                                         style="Accent.TButton",
                                         command=self._inbox_accept_all)
        self.btn_accept_all.pack(side="left")
        ttk.Button(ibrow1, text="Принять выбранное",
                   command=self._inbox_accept).pack(side="left", padx=(px(6), 0))
        ttk.Button(ibrow1, text="Отклонить выбранное",
                   command=self._inbox_decline).pack(side="left", padx=(px(6), 0))
        ttk.Button(ibrow2, text="Принять все от этого ПК",
                   command=self._inbox_accept_host).pack(side="left")
        self._btn_mute = ttk.Button(ibrow2, text=f"Игнор {self.opts['mute_min']} мин",
                                    command=self._inbox_mute)
        self._btn_mute.pack(side="left", padx=(px(6), 0))
        ttk.Button(ibrow2, text="Отклонить все",
                   command=self._inbox_decline_all).pack(side="left", padx=(px(6), 0))
        ib_wrap, self.inbox_tree = self._tree(
            ib, ("kind", "from", "what", "size"),
            {"kind": ("Тип", 64, "w"), "from": ("От", 130, "w"),
             "what": ("Что", 260, "w"), "size": ("Размер", 90, "e")}, height=3,
            selectmode="extended")
        ib_wrap.pack(fill="both", expand=True, pady=(px(8), 0))
        self.inbox_tree.bind("<Return>", lambda e: self._inbox_accept())
        self.inbox_tree.bind("<Delete>", lambda e: self._inbox_decline())
        self.inbox_tree.bind("<Double-1>", lambda e: self._inbox_accept())
        self.inbox_tree.bind("<Control-a>", self._inbox_select_all)

        # --- 2.1.5. Список машин в сети (двойной клик = подключение) ---
        lf1, c1 = self._card(tab, "Машины в сети",
                             "двойной клик — войти · правый клик — меню")
        cards["peers"] = lf1
        # нижние элементы упаковываются первыми — в тесном окне их не обрежет список
        ttk.Button(c1, text="По адресу IP:порт…",
                   command=self._manual_connect).pack(side="bottom", anchor="w",
                                                      pady=(px(6), 0))
        # --- 2.1.6. Поле кода комнаты и кнопка «Войти» ---
        joinrow = ttk.Frame(c1, style="Card.TFrame")
        joinrow.pack(side="bottom", fill="x", pady=(px(10), 0))
        ttk.Label(joinrow, text="Код комнаты", style="CardMuted.TLabel").pack(side="left")
        self.ent_code = ttk.Entry(joinrow, width=9, justify="center", font=F["mono"])
        self.ent_code.pack(side="left", padx=(px(8), px(8)))
        self.ent_code.bind("<Return>", lambda e: self._join_by_code())
        ttk.Button(joinrow, text="Войти", style="Accent.TButton",
                   command=self._join_by_code).pack(side="left")
        tree_wrap, self.tree = self._tree(
            c1, ("host", "ip", "room"),
            {"host": ("Имя ПК", 170, "w"), "ip": ("IP-адрес", 120, "w"),
             "room": ("Комната", 110, "center")}, height=5)
        tree_wrap.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", self._on_connect)
        self.tree.bind("<Button-3>", self._tree_menu)

        # --- 2.1.7. Участники комнаты с чекбоксами ---
        lf2, c2 = self._card(tab, "Участники комнаты")
        cards["members"] = lf2
        selrow = ttk.Frame(c2, style="Card.TFrame")
        selrow.pack(fill="x")
        self.all_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(selrow, text="Отправить всем", variable=self.all_var,
                        style="Card.TCheckbutton",
                        command=self._toggle_all).pack(side="left")
        ttk.Separator(c2, orient="horizontal").pack(fill="x", pady=(px(4), px(6)))
        self.members_frame = ttk.Frame(c2, style="Card.TFrame")
        self.members_frame.pack(fill="both", expand=True)

        # --- 2.1.8–2.1.10. Отправка файлов: зона drop, список, кнопки ---
        lf8, c8 = self._card(tab, "Отправка файлов",
                             "двойной клик по файлу в списке — убрать")
        cards["send"] = lf8

        btns = ttk.Frame(c8, style="Card.TFrame")
        btns.pack(side="bottom", fill="x", pady=(px(8), 0))
        brow = ttk.Frame(btns, style="Card.TFrame")
        brow.pack(fill="x")
        ttk.Button(brow, text="+ Файлы…",
                   command=self._browse_files).pack(side="left")
        ttk.Button(brow, text="+ Папку…",
                   command=self._browse_folder).pack(side="left", padx=(px(6), 0))
        ttk.Button(brow, text="Очистить",
                   command=self._clear_pending).pack(side="left", padx=(px(6), 0))
        srow = ttk.Frame(btns, style="Card.TFrame")
        srow.pack(fill="x", pady=(px(8), 0))
        self.btn_send = ttk.Button(srow, text="Отправить", style="Accent.TButton",
                                   command=self._send_files)
        self.btn_send.pack(side="right")
        self.lbl_files = ttk.Label(srow, text="Файлы не выбраны",
                                   style="CardMuted.TLabel")
        self.lbl_files.pack(side="left")

        self.drop = tk.Canvas(c8, width=10, height=px(82), bg=C.SURFACE, bd=0,
                              highlightthickness=0, cursor="hand2")
        self.drop.pack(fill="x")
        self._drop_hot = False
        self.drop.bind("<Configure>", lambda e: self._draw_drop())
        self.drop.bind("<Enter>", lambda e: self._draw_drop(True))
        self.drop.bind("<Leave>", lambda e: self._draw_drop(False))
        self.drop.bind("<Button-1>", lambda e: self._browse_files())
        if HAS_DND:
            self.drop.drop_target_register(DND_FILES)
            self.drop.dnd_bind("<<Drop>>", self._on_drop)
            self.drop.dnd_bind("<<DropEnter>>",
                               lambda e: (self._draw_drop(True), e.action)[1])
            self.drop.dnd_bind("<<DropLeave>>",
                               lambda e: (self._draw_drop(False), e.action)[1])

        lw, self.list_files = self._listbox(c8, 4)
        lw.pack(fill="both", expand=True, pady=(px(8), 0))
        for full, rel in self.pending_files:
            self.list_files.insert("end", self._list_label(full, rel))
        self.list_files.bind("<Double-1>", lambda e: self._remove_pending())
        self.list_files.bind("<Delete>", lambda e: self._remove_pending())
        self.root.bind("<Control-o>", lambda e: self._browse_files())
        if HAS_DND:
            self.list_files.drop_target_register(DND_FILES)
            self.list_files.dnd_bind("<<Drop>>", self._on_drop)

        # --- 2.1.10a/2.1.12. Журнал событий + сообщение получателям ---
        lf12, c12 = self._card(tab, "Журнал и сообщения")
        cards["log"] = lf12

        chat = ttk.Frame(c12, style="Card.TFrame")
        chat.pack(side="bottom", fill="x", pady=(px(8), 0))
        ttk.Label(chat, text="Сообщение выбранным получателям",
                  style="CardMuted.TLabel").pack(anchor="w", pady=(0, px(3)))
        self.ent_chat = ttk.Entry(chat)
        self.ent_chat.pack(fill="x")
        self.ent_chat.bind("<Return>", lambda e: self._send_chat())
        chatrow = ttk.Frame(chat, style="Card.TFrame")
        chatrow.pack(fill="x", pady=(px(6), 0))
        ttk.Button(chatrow, text="Отправить текст", style="Accent.TButton",
                   command=self._send_chat).pack(side="left")
        ttk.Button(chatrow, text="Из буфера",
                   command=self._send_clipboard).pack(side="left", padx=(px(6), 0))

        logwrap = tk.Frame(c12, bg=C.SURFACE2)
        logwrap.pack(side="top", fill="both", expand=True)
        self.log = tk.Text(logwrap, height=7, width=10, state="disabled", wrap="word",
                           font=F["log"], bg=C.SURFACE2, fg=C.TEXT,
                           insertbackground=C.TEXT, selectbackground=C.SEL,
                           relief="flat", bd=0, highlightthickness=0,
                           padx=px(10), pady=px(8), spacing1=px(1), spacing3=px(1))
        lsb = ttk.Scrollbar(logwrap, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=lsb.set)
        lsb.pack(side="right", fill="y")
        self.log.pack(side="left", fill="both", expand=True)
        for tag, col in (("ts", C.FAINT), ("msg", C.TEXT), ("ok", C.OK),
                         ("err", C.DANGER_HI), ("warn", C.WARN),
                         ("chat", C.ACCENT_HI)):
            self.log.tag_configure(tag, foreground=col)

        # =====================================================================
        # Страница «История»
        # =====================================================================
        ht = add_page("history", "История")
        ht.columnconfigure(0, weight=1)
        ht.rowconfigure(0, weight=1)
        lf7, c7 = self._card(
            ht, "История передач",
            f"хранятся последние {HISTORY_LIMIT} · двойной клик — открыть папку")
        lf7.grid(row=0, column=0, sticky="nsew", pady=(0, gap))
        hist_wrap, self.hist_tree = self._tree(
            c7, ("ts", "dir", "name", "peer", "size", "status"),
            {"ts": ("Время", 150, "w"), "dir": ("Направление", 100, "w"),
             "name": ("Файл", 260, "w"), "peer": ("ПК", 120, "w"),
             "size": ("Размер", 90, "e"), "status": ("Статус", 100, "w")},
            height=5)
        hist_wrap.pack(fill="both", expand=True)
        self.hist_tree.bind("<Double-1>", lambda e: self._open_history_path())
        hb = ttk.Frame(ht)
        hb.grid(row=1, column=0, sticky="ew")
        ttk.Button(hb, text="Открыть папку",
                   command=self._open_history_path).pack(side="left")
        ttk.Button(hb, text="Очистить историю",
                   command=self._clear_history).pack(side="left", padx=(px(6), 0))
        ht.bind("<Configure>", lambda e: self._layout_history(e.width), add="+")

        # =====================================================================
        # Страница «Бан»
        # =====================================================================
        bt = add_page("bans", "Бан")
        bt.columnconfigure(0, weight=1)
        bt.rowconfigure(0, weight=1)
        lf5, c5 = self._card(bt, "Забаненные ПК",
                             "сохраняется между запусками программы")
        lf5.grid(row=0, column=0, sticky="nsew", pady=(0, gap))
        bw, self.ban_list = self._listbox(c5, 5)
        bw.pack(fill="both", expand=True)
        bb = ttk.Frame(bt)
        bb.grid(row=1, column=0, sticky="ew")
        ttk.Button(bb, text="Разбанить выбранного",
                   command=self._unban_selected).pack(anchor="w")
        ban_hint = ttk.Label(
            bb, style="Muted.TLabel", justify="left",
            text="Бан выдаёт администратор комнаты кнопкой «...» у участника.")
        ban_hint.pack(anchor="w", pady=(px(6), 0))
        self._autowrap(ban_hint, bb, margin=4)

        # =====================================================================
        # Страница «Настройки» (с прокруткой)
        # =====================================================================
        st_page = add_page("settings", "Настройки", scroll=True)
        st_page.columnconfigure(0, weight=1)
        st_row = [0]

        def scard(title, hint=None):
            f, c = self._card(st_page, title, hint)
            f.grid(row=st_row[0], column=0, sticky="ew", pady=(0, gap))
            st_row[0] += 1
            return c

        def spin(parent, text, key, suffix=""):
            """Строка «подпись — число»; значение сохраняется сразу при вводе."""
            r = ttk.Frame(parent, style="Card.TFrame")
            r.pack(fill="x", pady=(px(4), 0))
            lo, hi = OPT_RANGE[key]
            var = tk.StringVar(value=str(self.opts[key]))
            sp = ttk.Spinbox(r, from_=lo, to=hi, width=8, textvariable=var,
                             justify="right")
            sp.pack(side="right")
            if suffix:
                ttk.Label(r, text=suffix, style="CardMuted.TLabel").pack(
                    side="right", padx=(0, px(6)))
            ttk.Label(r, text=text, style="Card.TLabel").pack(side="left")
            var.trace_add("write", lambda *a, k=key, v=var: self._set_opt(k, v.get()))
            sp.bind("<FocusOut>", lambda e, k=key, v=var: v.set(str(self.opts[k])))
            return sp

        def check(parent, text, key, hint=None):
            var = tk.BooleanVar(value=bool(self.opts[key]))
            ttk.Checkbutton(parent, text=text, style="Card.TCheckbutton", variable=var,
                            command=lambda: self._set_opt(key, var.get())).pack(
                                anchor="w", pady=(px(4), 0))
            if hint:
                lab = ttk.Label(parent, style="CardMuted.TLabel", justify="left",
                                text=hint)
                lab.pack(anchor="w", padx=(px(24), 0))
                self._autowrap(lab, parent, margin=32)

        def combo(parent, text, key, labels, width=26):
            """Выпадающий список: labels — словарь «значение настройки -> подпись»."""
            r = ttk.Frame(parent, style="Card.TFrame")
            r.pack(fill="x", pady=(px(4), 0))
            ttk.Label(r, text=text, style="Card.TLabel").pack(side="left")
            vals = list(labels.values())
            cb = ttk.Combobox(r, state="readonly", width=width, values=vals)
            cb.set(labels.get(self.opts[key], vals[0]))
            cb.pack(side="right")
            back = {v: k for k, v in labels.items()}
            cb.bind("<<ComboboxSelected>>",
                    lambda e, k=key, c=cb, b=back: self._set_opt(k, b.get(c.get())))
            return cb

        def note(parent, text, style="CardMuted.TLabel", top=6):
            lab = ttk.Label(parent, style=style, justify="left", text=text)
            lab.pack(anchor="w", pady=(px(top), 0))
            self._autowrap(lab, parent)
            return lab

        # --- Профиль ---
        c = scard("Этот ПК", "как вас видят другие")
        r = ttk.Frame(c, style="Card.TFrame")
        r.pack(fill="x")
        ttk.Label(r, text="Имя в сети", style="Card.TLabel").pack(side="left")
        self.ent_name = ttk.Entry(r, width=24)
        self.ent_name.pack(side="right")
        self.ent_name.insert(0, self.opts["device_name"])
        self.ent_name.bind("<Return>", lambda e: self._apply_name())
        self.ent_name.bind("<FocusOut>", lambda e: self._apply_name())
        note(c, f"Пусто — имя компьютера ({hostname()}). Новое имя увидят при "
                f"следующем подключении.")

        # --- Внешний вид ---
        c = scard("Внешний вид")
        cb = combo(c, "Размер шрифта", "font_size",
                   {n: f"{n} pt" for n in range(OPT_RANGE["font_size"][0],
                                                OPT_RANGE["font_size"][1] + 1)}, width=10)
        cb.bind("<<ComboboxSelected>>", self._on_font_size, add="+")
        check(c, "Звук при уведомлениях", "sound")
        note(c, "Тема переключается кнопкой в шапке.")

        # --- Папка и приём ---
        c = scard("Папка для принятых файлов", "сюда сохраняются файлы от других ПК")
        row = ttk.Frame(c, style="Card.TFrame")
        row.pack(fill="x")
        ttk.Button(row, text="Обзор…",
                   command=self._choose_dir).pack(side="right", padx=(px(8), 0))
        self.ent_dir = ttk.Entry(row)
        self.ent_dir.pack(side="left", fill="x", expand=True)
        self.ent_dir.insert(0, self.download_dir)
        self.ent_dir.bind("<Return>", lambda e: self._apply_dir_entry())
        self.ent_dir.bind("<FocusOut>", lambda e: self._apply_dir_entry())
        check(c, "Раскладывать по папкам отправителей", "subfolders")
        combo(c, "Если файл уже есть", "on_conflict",
              {"rename": "добавить номер: файл (1)", "overwrite": "перезаписать"})

        c = scard("Приём файлов")
        row6 = ttk.Frame(c, style="Card.TFrame")
        row6.pack(fill="x")
        ttk.Label(row6, text="Входящие файлы", style="Card.TLabel").pack(side="left")
        self.cmb_receive = ttk.Combobox(
            row6, state="readonly", width=24,
            values=("принимать автоматически", "спрашивать", "отклонять"))
        self.cmb_receive.current({"auto": 0, "ask": 1, "reject": 2}.get(self.receive_mode, 1))
        self.cmb_receive.pack(side="right")
        self.cmb_receive.bind("<<ComboboxSelected>>", lambda e: self._set_receive_mode())
        check(c, "Доверять избранным ПК (★): принимать их файлы без вопросов", "trust_favs",
              "Работает в режиме «спрашивать». Избранное задаётся правым кликом по машине "
              "в списке.")
        spin(c, "Автоприём только файлов до", "auto_limit_mb", "МБ")
        note(c, "0 — без ограничения. Файлы крупнее лимита будут появляться во «Входящих» "
                "и ждать вашего решения.", top=2)
        self.var_hash = tk.BooleanVar(value=self.verify_hash)
        ttk.Checkbutton(c, text="Проверять контрольную сумму SHA-256",
                        style="Card.TCheckbutton", variable=self.var_hash,
                        command=self._set_verify_hash).pack(anchor="w", pady=(px(6), 0))
        note(c, "Надёжнее: повреждённый файл будет отброшен. Передача начинается чуть позже.",
             top=0)

        # --- Комната ---
        c = scard("Комната")
        combo(c, "Доступ по умолчанию", "default_access",
              {"public": "публичная", "code": "только по коду"}, width=18)
        check(c, "Создавать комнату при запуске программы", "autostart")

        # --- Приватность и защита ---
        c = scard("Приватность")
        ttk.Checkbutton(
            c, text="Показывать себя в сети",
            style="Card.TCheckbutton", variable=self.visible,
            command=self._save_config).pack(anchor="w")
        note(c, "Если выключить, этот ПК не объявляет себя в сети и игнорирует "
                "UDP-сканирование.", top=0)

        c = scard("Защита от спама и перебора", "действует сразу")
        spin(c, "Автоотказ по запросу файла через", "inbox_ttl", "с")
        spin(c, "Игнорировать отправителя", "mute_min", "мин")
        spin(c, "Неверных кодов до блокировки IP", "max_fails")
        spin(c, "Блокировка IP на", "block_min", "мин")

        # --- Сеть ---
        c = scard("Сеть", "порт — после перезапуска")
        spin(c, "TCP-порт", "tcp_port")
        spin(c, "Объявлять себя каждые", "announce_period", "с")
        spin(c, "Забывать молчащие машины через", "peer_ttl", "с")
        if self.ssl_srv:
            note(c, "Шифрование включено: TLS, самоподписанный сертификат",
                 style="CardOk.TLabel", top=8)
        else:
            note(c, "Шифрование выключено — установите пакет cryptography "
                    "(pip install cryptography)", style="CardWarn.TLabel", top=8)
        note(c, f"Сейчас: TCP-порт {self.tcp_port} · UDP-порт обнаружения {UDP_PORT} · "
                f"протокол v{PROTO_VER}", top=4)

        # --- Сброс ---
        rb = ttk.Frame(st_page)
        rb.grid(row=st_row[0], column=0, sticky="w", pady=(0, px(4)))
        ttk.Button(rb, text="Сбросить настройки по умолчанию",
                   command=self._reset_opts).pack(side="left")

        # --- раскладка под текущую ширину окна ---
        w0 = self.root.winfo_width()
        if w0 < 200:
            w0 = getattr(self, "_init_w", px(1020))
        w0 -= px(28)
        self._layout_header(w0)
        self._layout_send(w0)
        self._layout_history(w0)
        outer.bind("<Configure>", lambda e: self._layout_header(e.width), add="+")
        self._scrolls["send"].canvas.bind(
            "<Configure>", lambda e: self._layout_send(e.width), add="+")
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.root.bind_all(seq, self._on_wheel)

        for entry in self._log_buf:           # журнал переживает смену темы
            self._write_log(*entry)
        self._show_page(self._cur_page)
        self._show_room(self.room)
        if self.is_admin:
            self.lbl_admin.config(text="Вы администратор")
        self._update_pending_info()
        self._refresh_bans()
        self._refresh_history()
        self._refresh_tree()
        self._refresh_members()
        self._refresh_progress()
        self._inbox_fill()
        if first:
            self._log("Программа запущена. Нажмите «Запустить сервер», чтобы создать комнату.")

    # --- 2.1.1a. Адаптивная раскладка ------------------------------------

    def _layout_header(self, w):
        """Шапка: в широком окне — в одну строку; в среднем навигация уходит вниз;
        в самом узком статус и навигация идут отдельными строками."""
        if not hasattr(self, "_header"):
            return
        px = self.px
        tier = 0 if w >= px(1060) else 1 if w >= px(700) else 2
        # в узком окне длинная строка «Этот ПК…» переносится
        self.lbl_me.configure(wraplength=max(px(180), w - px(90)) if tier == 2 else 0)
        if tier == self._hdr_key:
            return
        self._hdr_key = tier
        h = self._header
        for wd in (self._brand, self._navbar, self._hright):
            wd.grid_forget()
        h.columnconfigure(0, weight=0)
        h.columnconfigure(1, weight=1)
        if tier == 0:
            self._brand.grid(row=0, column=0, sticky="w")
            self._navbar.grid(row=0, column=1, sticky="w", padx=(px(20), 0))
            self._hright.grid(row=0, column=2, sticky="e")
        elif tier == 1:
            self._brand.grid(row=0, column=0, sticky="w")
            self._hright.grid(row=0, column=1, columnspan=2, sticky="e")
            self._navbar.grid(row=1, column=0, columnspan=3, sticky="w",
                              pady=(px(8), 0))
        else:
            self._brand.grid(row=0, column=0, columnspan=3, sticky="w")
            self._hright.grid(row=1, column=0, columnspan=3, sticky="e",
                              pady=(px(8), 0))
            self._navbar.grid(row=2, column=0, columnspan=3, sticky="w",
                              pady=(px(8), 0))

    def _layout_send(self, w):
        """Страница «Обмен»: две колонки при ширине от 860 px, иначе одна."""
        if not hasattr(self, "_send_cards"):
            return
        px = self.px
        wide = w >= px(860)
        compact = w < px(640)
        if (wide, compact) == self._send_key:
            return
        self._send_key = (wide, compact)
        page, c, gap = self._send_page, self._send_cards, px(12)
        for card in c.values():
            card.grid_forget()
        for i in range(8):
            page.rowconfigure(i, weight=0)
        for i in range(2):
            page.columnconfigure(i, weight=0, minsize=0)
        if wide:
            page.columnconfigure(0, weight=3, minsize=px(320))
            page.columnconfigure(1, weight=2, minsize=px(260))
            c["room"].grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, gap))
            c["inbox"].grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, gap))
            c["peers"].grid(row=2, column=0, sticky="nsew", padx=(0, gap), pady=(0, gap))
            c["members"].grid(row=2, column=1, sticky="nsew", pady=(0, gap))
            c["send"].grid(row=3, column=0, sticky="nsew", padx=(0, gap),
                           pady=(0, px(4)))
            c["log"].grid(row=3, column=1, sticky="nsew", pady=(0, px(4)))
            page.rowconfigure(2, weight=1)
            page.rowconfigure(3, weight=1)
        else:
            page.columnconfigure(0, weight=1)
            for i, key in enumerate(("room", "inbox", "peers", "members", "send", "log")):
                c[key].grid(row=i, column=0, sticky="ew" if i < 2 else "nsew",
                            pady=(0, gap) if i < 5 else (0, px(4)))
            for i in (2, 4, 5):
                page.rowconfigure(i, weight=1)
        self._layout_room(compact)
        self._inbox_sync()

    def _layout_room(self, compact):
        """Карточка комнаты: в узком окне элементы идут столбиком."""
        rc, px = self._rc, self.px
        for wd in (self.btn_server, self._rc_sep, self._rc_code, self._rc_acc):
            wd.grid_forget()
        for i in range(5):
            rc.columnconfigure(i, weight=0)
        if compact:
            rc.columnconfigure(0, weight=1)
            self.btn_server.grid(row=0, column=0, sticky="ew")
            self._rc_code.grid(row=1, column=0, sticky="w", pady=(px(10), 0))
            self._rc_acc.grid(row=2, column=0, sticky="w", pady=(px(10), 0))
        else:
            rc.columnconfigure(3, weight=1)
            self.btn_server.grid(row=0, column=0, sticky="w")
            self._rc_sep.grid(row=0, column=1, sticky="ns", padx=px(18))
            self._rc_code.grid(row=0, column=2, sticky="w")
            self._rc_acc.grid(row=0, column=4, sticky="e")

    def _layout_history(self, w):
        """История: в узком окне остаются только самые важные столбцы."""
        if not hasattr(self, "hist_tree"):
            return
        compact = w < self.px(760)
        if compact == self._hist_key:
            return
        self._hist_key = compact
        self.hist_tree.configure(
            displaycolumns=("dir", "name", "status") if compact else "#all")

    def _on_wheel(self, e):
        """Колесо мыши прокручивает страницу, если она не помещается в окно."""
        sf = self._scrolls.get(self._cur_page) if hasattr(self, "_scrolls") else None
        if not sf or not sf.needs_scroll():
            return
        w = e.widget
        try:
            if not str(w).startswith(str(sf.canvas)):
                return
            if w.winfo_class() in ("Text", "Listbox", "Treeview"):
                lo, hi = w.yview()
                if lo > 0.0 or hi < 1.0:      # у списка есть своя прокрутка — не мешаем
                    return
        except (tk.TclError, ValueError, TypeError):
            return
        num = getattr(e, "num", None)
        if num == 4:
            step = -1
        elif num == 5:
            step = 1
        else:
            delta = getattr(e, "delta", 0) or 0
            step = -1 if delta > 0 else 1 if delta < 0 else 0
        if step:
            sf.canvas.yview_scroll(step * 3, "units")

    def _toggle_theme(self):
        self.theme = "light" if self.theme == "dark" else "dark"
        C.apply(self.theme)
        self._save_config()
        self._rebuild_ui()

    def _rebuild_ui(self):
        """Пересобрать окно в новой теме, сохранив введённое и выбранное."""
        keep = {"code": self.ent_code.get(), "chat": self.ent_chat.get(),
                "access": self.cmb_access.current(),
                "sel": {mid: v.get() for mid, v in self.member_vars.items()}}
        if self._toast_job:
            try:
                self.root.after_cancel(self._toast_job)
            except Exception:
                pass
            self._toast_job = None
        self._outer.destroy()
        self._build_ui(first=False)
        self.ent_code.insert(0, keep["code"])
        self.ent_chat.insert(0, keep["chat"])
        self.cmb_access.current(keep["access"] if keep["access"] in (0, 1) else 0)
        for mid, val in keep["sel"].items():
            if mid in self.member_vars:
                self.member_vars[mid].set(val)
        if self.member_vars:
            self.all_var.set(all(v.get() for v in self.member_vars.values()))

    # --- Блок 2.2. Вход в комнату: двойной клик и диалог кода -------------

    def _on_connect(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            self._log("Сначала выберите машину в списке слева.")
            return
        peer = dict(self._tree_rows.get(sel[0]) or {})
        if not peer.get("port"):
            self._log("Эта машина сейчас недоступна — включите LAN Share на ней.")
            return
        peer["join_code"] = ""
        if peer.get("access") == "code":
            code = self._norm_code(self.ent_code.get()) or self._ask_code(peer)
            if not code:
                return
            peer["join_code"] = code
            self.ent_code.delete(0, "end")
            self.ent_code.insert(0, code)
        threading.Thread(target=self._connect_peer, args=(peer,), daemon=True).start()

    def _dialog(self, title):
        """Заготовка модального окна в общем стиле. Возвращает (окно, тело)."""
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.configure(bg=C.BG)
        dlg.transient(self.root)
        dlg.resizable(False, False)
        body = ttk.Frame(dlg, padding=(self.px(26), self.px(22)))
        body.pack(fill="both", expand=True)
        return dlg, body

    def _run_dialog(self, dlg, focus=None):
        """Показать окно по центру главного и дождаться закрытия."""
        dlg.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - dlg.winfo_reqwidth()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - dlg.winfo_reqheight()) // 3
        dlg.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        if focus is not None:
            focus.focus_set()
        try:
            dlg.wait_visibility()
            dlg.grab_set()
        except tk.TclError:
            pass
        self.root.wait_window(dlg)

    def _ask_code(self, peer):
        """Модальный диалог: ввод кода комнаты. Возвращает код или None."""
        dlg, body = self._dialog("Вход в комнату")
        result = {}
        F, px = self.F, self.px

        title = f"Комната {peer['room']}" if peer.get("room") else "Закрытая комната"
        ttk.Label(body, text=title, font=F["big"]).pack(anchor="w")
        ttk.Label(body, text="Для входа нужен код — его покажет администратор.",
                  style="Muted.TLabel").pack(anchor="w", pady=(px(2), px(14)))
        e_code = ttk.Entry(body, width=12, justify="center", font=(F["code"][0], 16, "bold"))
        e_code.pack(fill="x")

        btns = ttk.Frame(body)
        btns.pack(fill="x", pady=(px(18), 0))

        def submit():
            result["code"] = self._norm_code(e_code.get())
            dlg.destroy()

        ttk.Button(btns, text="Войти", style="Accent.TButton",
                   command=submit).pack(side="right")
        ttk.Button(btns, text="Отмена", command=dlg.destroy).pack(side="right", padx=(0, px(8)))
        dlg.bind("<Return>", lambda e: submit())
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        self._run_dialog(dlg, e_code)
        return result.get("code") or None

    # --- 2.2a. Избранное и подключение по адресу IP:порт ------------------

    def _tree_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        info = dict(self._tree_rows.get(iid) or {})
        ip = info.get("ip")
        if not ip:
            return
        menu = self._menu()
        if ip in self.favorites:
            menu.add_command(label="Убрать из избранных",
                             command=lambda: self._remove_favorite(ip))
        else:
            menu.add_command(label="Добавить в избранные",
                             command=lambda: self._add_favorite(info))
        menu.add_command(label="Подключиться", command=self._on_connect)
        menu.add_command(label="Подключиться по адресу…", command=self._manual_connect)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _add_favorite(self, info):
        ip = info.get("ip")
        port = info.get("port")
        if not ip or not port:
            return
        with self.lock:
            self.favorites[ip] = {"host": info.get("host") or ip, "ip": ip,
                                  "port": int(port)}
        self._save_config()
        self._refresh_tree()
        self._log(f"Добавлено в избранные: {self.favorites[ip]['host']} ({ip})")

    def _remove_favorite(self, ip):
        with self.lock:
            info = self.favorites.pop(ip, None)
        if info:
            self._save_config()
            self._refresh_tree()
            self._log(f"Убрано из избранных: {info['host']} ({ip})")

    def _manual_connect(self):
        """Диалог «IP:порт» для сетей, где UDP-обнаружение не проходит."""
        dlg, body = self._dialog("Подключиться по адресу")
        F, px = self.F, self.px
        ttk.Label(body, text="Адрес удалённого ПК", font=F["big"]).pack(anchor="w")
        ttk.Label(body, text="Формат: IP:порт — например, 192.168.0.10:%d" % self.opts["tcp_port"],
                  style="Muted.TLabel").pack(anchor="w", pady=(px(2), px(12)))
        e_addr = ttk.Entry(body, width=28, font=F["mono"])
        e_addr.insert(0, f"192.168.0.10:{self.opts['tcp_port']}")
        e_addr.pack(fill="x")
        ttk.Label(body, text="Код комнаты (если требуется)",
                  style="Muted.TLabel").pack(anchor="w", pady=(px(12), px(3)))
        e_code = ttk.Entry(body, width=12, font=F["mono"])
        e_code.pack(fill="x")

        def go():
            raw = e_addr.get().strip()
            code = self._norm_code(e_code.get())
            dlg.destroy()
            self._connect_address(raw, code)

        btns = ttk.Frame(body)
        btns.pack(fill="x", pady=(px(18), 0))
        ttk.Button(btns, text="Подключиться", style="Accent.TButton",
                   command=go).pack(side="right")
        ttk.Button(btns, text="Отмена", command=dlg.destroy).pack(side="right", padx=(0, px(8)))
        dlg.bind("<Return>", lambda e: go())
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        e_addr.select_range(0, "end")
        self._run_dialog(dlg, e_addr)

    def _connect_address(self, raw, code=""):
        raw = (raw or "").strip()
        if not raw:
            return
        if ":" in raw:
            host, _, port = raw.rpartition(":")
        else:
            host, port = raw, str(self.opts["tcp_port"])
        host = host.strip()
        try:
            port = int(port)
        except ValueError:
            self._log(f"Неверный адрес: {raw} (нужно IP:порт)")
            return
        if not host:
            return
        peer = {"id": "manual:" + host, "host": host, "ip": host, "port": port,
                "join_code": code}
        self._log(f"Подключение по адресу {host}:{port}…")
        threading.Thread(target=self._connect_peer, args=(peer,), daemon=True).start()

    # --- 2.2b. Чат и буфер обмена -----------------------------------------

    def _send_control(self, msg, targets):
        """Отправить управляющее сообщение по контрольным сокетам участников."""
        data = (json.dumps(msg) + "\n").encode("utf-8")
        delivered = 0
        with self._ctl_lock:
            for m in targets:
                sock = m.get("sock")
                if sock is None:
                    continue
                try:
                    sock.sendall(data)
                    delivered += 1
                except OSError as e:
                    self._log(f"Не удалось отправить {m.get('host')}: {e}")
        return delivered

    def _send_chat(self):
        text = self.ent_chat.get().strip()
        if not text:
            return
        members = self._selected_targets()
        if not members:
            self._set_toast("Отметьте получателей галочками", sound=False, warn=True)
            return
        delivered = self._send_control(
            {"type": "chat", "text": text[:4000], "kind": "text"}, members)
        if delivered:
            flat = text.replace("\r", " ").replace("\n", " / ")
            self._append_log(f"Чат · Вы: {flat[:500]}")
            self.ent_chat.delete(0, "end")
        else:
            self._log("Сообщение не доставлено: нет прямого соединения с получателями")

    def _send_clipboard(self):
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            self._set_toast("В буфере обмена нет текста", sound=False, warn=True)
            return
        members = self._selected_targets()
        if not members:
            self._set_toast("Отметьте получателей галочками", sound=False, warn=True)
            return
        delivered = self._send_control(
            {"type": "chat", "text": text[:8000], "kind": "clipboard"}, members)
        if delivered:
            self._append_log(f"Чат · отправлен текст из буфера ({len(text)} симв.)")

    # --- Блок 2.3. Файлы: drag-and-drop, проводник, список отправки -------

    def _on_drop(self, event):
        for f in self.root.tk.splitlist(event.data):
            self._add_pending(f)      # файл или папка
        self._draw_drop(False)
        return COPY

    def _browse_files(self):
        for f in filedialog.askopenfilenames(title="Выберите файлы для отправки"):
            self._add_pending(f)

    def _browse_folder(self):
        d = filedialog.askdirectory(title="Выберите папку для отправки")
        if d:
            self._add_pending(d)

    def _add_pending(self, path, rel=None):
        """Файл или папка (рекурсивно). rel — относительный путь для сохранения структуры."""
        if os.path.isdir(path):
            base = os.path.dirname(os.path.abspath(path))
            for root, _dirs, files in os.walk(path):
                for name in files:
                    full = os.path.join(root, name)
                    self._add_file(full, os.path.relpath(full, base))
        elif os.path.isfile(path):
            self._add_file(path, rel or os.path.basename(path))

    def _add_file(self, full, rel):
        item = (full, rel.replace("\\", "/"))
        if item not in self.pending_files:
            self.pending_files.append(item)
            self.list_files.insert("end", self._list_label(full, item[1]))
            self._update_pending_info()

    def _list_label(self, full, rel):
        try:
            return f"{rel}   ·   {self._fmt_size(os.path.getsize(full))}"
        except OSError:
            return rel

    def _remove_pending(self):
        sel = self.list_files.curselection()
        if sel:
            self.pending_files.pop(sel[0])
            self.list_files.delete(sel[0])
            self._update_pending_info()

    def _clear_pending(self):
        self.pending_files.clear()
        self.list_files.delete(0, "end")
        self._update_pending_info()

    # --- Блок 2.4. Чекбоксы получателей и меню участника ------------------

    def _toggle_all(self):
        value = self.all_var.get()
        for var in self.member_vars.values():
            var.set(value)

    def _sync_all(self):
        """Галочка «Отправить всем» отражает состояние отдельных галочек."""
        self.all_var.set(bool(self.member_vars)
                         and all(v.get() for v in self.member_vars.values()))

    def _member_menu(self, mid, widget):
        menu = self._menu()
        menu.add_command(label="Кикнуть из комнаты",
                         command=lambda: self._kick_member(mid))
        menu.add_command(label="Забанить (сохраняется между запусками)",
                         command=lambda: self._ban_member(mid))
        try:
            menu.tk_popup(widget.winfo_rootx(),
                          widget.winfo_rooty() + widget.winfo_height())
        finally:
            menu.grab_release()

    # --- Блок 2.5. Обновление интерфейса (только главный поток) -----------

    def _poll_ui(self):
        try:
            for _ in range(POLL_BATCH):      # остальное — на следующем такте, окно не виснет
                try:
                    kind, args = self.ui.get_nowait()
                except queue.Empty:
                    break
                try:
                    self._dispatch_ui(kind, args)
                except Exception as e:
                    self._append_log(f"Ошибка интерфейса ({kind}): {e}")
            now = time.time()
            if now - self._inbox_tick > 1.0:
                self._inbox_tick = now
                try:
                    self._inbox_expire()
                except Exception:
                    pass
        finally:
            try:
                self._poll_id = self.root.after(100, self._poll_ui)
            except tk.TclError:
                pass

    def _dispatch_ui(self, kind, args):
        if kind == "log":
            self._append_log(args[0])
        elif kind == "peers":
            self._refresh_tree()
        elif kind == "members":
            self._refresh_members()
        elif kind == "bans":
            self._refresh_bans()
        elif kind == "history":
            self._refresh_history()
        elif kind == "room":
            self._show_room(args[0])
        elif kind == "room_off":
            self._show_room(None)
        elif kind == "progress":
            self._refresh_progress()
        elif kind == "enable_send":
            if hasattr(self, "btn_send"):
                self.btn_send.config(state="normal")
        elif kind == "ask_file":
            self._ask_receive(*args)
        elif kind == "clipboard":
            self._on_clipboard(*args)
        elif kind == "toast":
            self._set_toast(args[0])

    def _set_toast(self, text, sound=True, warn=False):
        """Короткое сообщение в нижней панели (не окно). Звук — не чаще раза в 3 секунды."""
        if not hasattr(self, "lbl_toast"):
            return
        self.lbl_toast.config(text=text,
                              style="CardWarn.TLabel" if warn else "CardOk.TLabel")
        self.lbl_toast.grid()
        now = time.time()
        if sound and self.opts["sound"] and now - self._last_bell > 3.0:
            self._last_bell = now
            try:
                self.root.bell()
            except tk.TclError:
                pass
        if self._toast_job:
            try:
                self.root.after_cancel(self._toast_job)
            except Exception:
                pass
        self._toast_job = self.root.after(5000, self._clear_toast)

    def _clear_toast(self):
        self._toast_job = None
        try:
            self.lbl_toast.config(text="")
            self.lbl_toast.grid_remove()
        except (AttributeError, tk.TclError):
            pass

    # --- Блок 2.5a. Входящие запросы: панель в окне, без всплывающих окон ---

    def _inbox_blocked(self, host):
        """True, если запрос нужно молча отклонить (игнор или лимиты). В журнал пишет редко."""
        now = time.time()
        until = self.muted.get(host, 0)
        if until > now:
            blocked = True
        else:
            self.muted.pop(host, None)
            per = sum(1 for it in self.inbox.values() if it["host"] == host)
            blocked = per >= INBOX_PER_SENDER or len(self.inbox) >= INBOX_MAX
        if blocked:
            n = self._spam_cnt[host] = self._spam_cnt.get(host, 0) + 1
            if now - self._spam_log.get(host, 0) > 10:
                self._spam_log[host] = now
                self._append_log(f"Запросы от {host} отклоняются автоматически "
                                 f"(лимит или игнор), всего: {n}")
        return blocked

    def _ask_receive(self, name, sender, size, ev, box):
        """Запрос на приём файла: в панель «Входящие» (выполняется в главном потоке)."""
        if self._inbox_blocked(sender):
            box["ok"] = None            # тихий автоотказ
            ev.set()
            return
        self._inbox_add({"kind": "file", "host": sender, "name": name,
                         "size": size, "ev": ev, "box": box})
        self._set_toast(f"Запрос на файл от {sender}")

    def _on_clipboard(self, host, text):
        """Пришёл текст из буфера обмена: в панель «Входящие» (копирование — по кнопке)."""
        if self._inbox_blocked(host):
            return
        for it in self.inbox.values():          # одинаковый текст подряд не дублируем
            if it["kind"] == "text" and it["host"] == host and it["text"] == text:
                return
        self._inbox_add({"kind": "text", "host": host, "text": text})
        self._set_toast(f"Текст от {host}")

    def _inbox_row(self, item):
        if item["kind"] == "file":
            return ("Файл", item["host"], item["name"], self._fmt_size(item["size"]))
        flat = item["text"].replace("\r", " ").replace("\n", " / ")
        what = flat if len(flat) <= 120 else flat[:120] + "…"
        return ("Текст", item["host"], what, f"{len(item['text'])} симв.")

    def _inbox_insert(self, iid, item):
        if not hasattr(self, "inbox_tree"):
            return
        i = len(self.inbox_tree.get_children())
        self.inbox_tree.insert("", "end", iid=iid, values=self._inbox_row(item),
                               tags=("even" if i % 2 else "odd",))

    def _inbox_add(self, item):
        self._inbox_id += 1
        iid = str(self._inbox_id)
        item["t"] = time.time()
        self.inbox[iid] = item
        self._inbox_insert(iid, item)
        self._inbox_sync()

    def _inbox_fill(self):
        """Заполнить панель из состояния (после пересборки окна)."""
        for iid, item in self.inbox.items():
            self._inbox_insert(iid, item)
        self._inbox_sync()

    def _inbox_sync(self):
        """Показать панель, только пока в ней есть запросы; выделить первый."""
        if not hasattr(self, "inbox_card"):
            return
        n = len(self.inbox)
        try:      # число ожидающих запросов видно и в заголовке окна, и в панели задач
            self.root.title(f"({n}) LAN Share — обмен файлами в локальной сети" if n
                            else "LAN Share — обмен файлами в локальной сети")
        except tk.TclError:
            pass
        if n:
            files = [it for it in self.inbox.values() if it["kind"] == "file"]
            total = sum(it["size"] for it in files)
            extra = f" · файлов: {len(files)} на {self._fmt_size(total)}" if files else ""
            self.inbox_card.grid()
            self.lbl_inbox.config(text=f"Входящие запросы: {n}{extra}")
            if not self.inbox_tree.selection():
                kids = self.inbox_tree.get_children()
                if kids:
                    self.inbox_tree.selection_set(kids[0])
        else:
            self.inbox_card.grid_remove()

    def _inbox_resolve(self, iid, accept):
        item = self.inbox.pop(iid, None)
        if item is None:
            return
        if hasattr(self, "inbox_tree"):
            try:
                self.inbox_tree.delete(iid)
            except tk.TclError:
                pass
        if item["kind"] == "file":
            item["box"]["ok"] = bool(accept)
            item["ev"].set()
        elif accept:
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(item["text"])
                self._set_toast("Текст скопирован в буфер", sound=False)
            except tk.TclError:
                pass

    def _inbox_selected(self):
        return list(self.inbox_tree.selection()) if hasattr(self, "inbox_tree") else []

    def _inbox_accept(self):
        for iid in self._inbox_selected():
            self._inbox_resolve(iid, True)
        self._inbox_sync()

    def _inbox_decline(self):
        for iid in self._inbox_selected():
            self._inbox_resolve(iid, False)
        self._inbox_sync()

    def _inbox_select_all(self, _e=None):
        self.inbox_tree.selection_set(self.inbox_tree.get_children())
        return "break"

    def _inbox_accept_host(self):
        """Принять все файлы от того же ПК, что и у выбранного запроса (или у первого)."""
        sel = self._inbox_selected() or list(self.inbox)[:1]
        item = self.inbox.get(sel[0]) if sel else None
        if not item:
            return
        host = item["host"]
        for iid, it in list(self.inbox.items()):
            if it["host"] == host and it["kind"] == "file":
                self._inbox_resolve(iid, True)
        self._inbox_sync()

    def _inbox_accept_all(self):
        """Принять все файлы (тексты остаются: копировать их по одному нужно осознанно)."""
        for iid, it in list(self.inbox.items()):
            if it["kind"] == "file":
                self._inbox_resolve(iid, True)
        self._inbox_sync()

    def _inbox_decline_all(self):
        for iid in list(self.inbox):
            self._inbox_resolve(iid, False)
        self._inbox_sync()

    def _inbox_mute(self):
        """Игнорировать отправителя выбранного запроса на заданное время."""
        sel = self._inbox_selected()
        item = self.inbox.get(sel[0]) if sel else None
        if not item:
            self._set_toast("Выберите запрос в списке", sound=False, warn=True)
            return
        host = item["host"]
        self.muted[host] = time.time() + self.opts["mute_min"] * 60
        for iid, it in list(self.inbox.items()):
            if it["host"] == host:
                self._inbox_resolve(iid, False)
        self._inbox_sync()
        self._log(f"Игнорируем {host} в течение {self.opts['mute_min']} мин.")

    def _inbox_expire(self):
        """Запросы без ответа отклоняются сами, а не копятся."""
        now = time.time()
        changed = False
        for iid, it in list(self.inbox.items()):
            ttl = self.opts["inbox_ttl"] if it["kind"] == "file" else INBOX_TEXT_TTL
            if now - it["t"] > ttl:
                self._inbox_resolve(iid, False)
                changed = True
        if changed:
            self._inbox_sync()

    def _refresh_tree(self):
        if not hasattr(self, "tree"):
            return
        self.tree.delete(*self.tree.get_children())
        rows = {}
        with self.lock:
            peers = {p["ip"]: dict(p) for p in self.peers.values()}
            favs = {ip: dict(f) for ip, f in self.favorites.items()}
        for ip, p in peers.items():
            rows[p["id"]] = p
        for ip, f in favs.items():       # «избранные» видны, даже когда оффлайн
            if ip not in peers:
                rows["fav:" + ip] = {"id": "fav:" + ip, "host": f["host"], "ip": ip,
                                     "port": f["port"], "room": "", "access": "",
                                     "offline": True}
        self._tree_rows = {}
        items = sorted(rows.items(), key=lambda kv: kv[1]["host"].lower())
        for i, (iid, p) in enumerate(items):
            self._tree_rows[iid] = p
            host = ("* " if p["ip"] in favs else "") + p["host"]
            if p.get("offline"):
                room_txt = "оффлайн (избранное)"
            elif p.get("room"):
                room_txt = p["room"] + (" (код)" if p.get("access") == "code" else "")
            elif p.get("access") == "code":
                room_txt = "по коду"
            else:
                room_txt = "—"
            self.tree.insert("", "end", iid=iid,
                             tags=("even" if i % 2 else "odd",),
                             values=(host, p["ip"], room_txt))

    def _refresh_members(self):
        if not hasattr(self, "members_frame"):
            return
        old_sel = {mid: v.get() for mid, v in self.member_vars.items()}
        for w in self.members_frame.winfo_children():
            w.destroy()
        self.member_vars = {}
        with self.lock:
            rows = [(m, True) for m in self.members.values()]
            seen = {m["id"] for m in self.members.values()}
            rows += [(r, False) for mid, r in self.roster.items() if mid not in seen]
        rows.sort(key=lambda e: e[0]["host"].lower())
        if not rows:
            ttk.Label(self.members_frame, text="Пока никого нет",
                      style="CardMuted.TLabel").pack(pady=(self.px(14), self.px(2)))
            ttk.Label(self.members_frame,
                      text="Запустите сервер или войдите\nв чужую комнату по коду",
                      style="CardMuted.TLabel", justify="center").pack()
        for m, direct in rows:
            row = ttk.Frame(self.members_frame, style="Card.TFrame")
            row.pack(fill="x", pady=1)
            var = tk.BooleanVar(value=old_sel.get(m["id"], True))
            self.member_vars[m["id"]] = var
            star = "(админ) " if m.get("admin") else ("· " if not direct else "")
            ttk.Checkbutton(row, text=f'{star}{m["host"]}  ({m["ip"]})',
                            style="Card.TCheckbutton", variable=var,
                            command=self._sync_all).pack(side="left", fill="x")
            if self.is_admin and direct and hasattr(self, "_member_menu"):
                btn = ttk.Button(row, text="...", width=3, style="Mini.TButton")
                btn.pack(side="right")
                btn.configure(command=lambda mid=m["id"],
                              w=btn: self._member_menu(mid, w))
        self._sync_all()

    def _refresh_bans(self):
        if not hasattr(self, "ban_list"):
            return
        self.ban_list.delete(0, "end")
        with self.lock:
            items = sorted(self.banned.items(),
                           key=lambda kv: (kv[1].get("host") or kv[0]).lower())
        for ip, info in items:
            self.ban_list.insert("end", f'{info.get("host") or "?"} — {ip}')

    def _draw_progress(self, pct):
        if not hasattr(self, "pbar"):
            return
        self.pbar_val = max(0, min(100, int(pct)))
        w, h = (self.pbar.winfo_width() or 1), self.pbar_h
        mid = h / 2
        self.pbar.coords(self.pbar_trough, mid, mid, max(mid, w - mid), mid)
        if self.pbar_val <= 0:
            self.pbar.itemconfigure(self.pbar_fill, state="hidden")
            return
        x = max(mid, w * self.pbar_val / 100 - mid)
        self.pbar.coords(self.pbar_fill, mid, mid, x, mid)
        self.pbar.itemconfigure(self.pbar_fill, state="normal")

    def _refresh_progress(self):
        """Перерисовать полосу по активным передачам (главный поток)."""
        with self.lock:
            trs = list(self.transfers.values())
        if not trs:
            self._draw_progress(0)
            if hasattr(self, "lbl_prog"):
                self.lbl_prog.config(
                    text=f"Нет активных передач · за сеанс: отправлено "
                         f"{self._fmt_size(self.totals['out'])}, принято "
                         f"{self._fmt_size(self.totals['in'])}")
                self.lbl_prog.grid()
            if hasattr(self, "btn_cancel"):
                self.btn_cancel.config(state="disabled")
            return
        now = time.time()
        total = sum(t["size"] for t in trs)
        done = sum(min(t["sent"], t["size"]) for t in trs)
        speed = 0.0
        for t in trs:
            elapsed = max(now - t["t0"], 0.001)
            speed += max(t["sent"] - t["base"], 0) / elapsed
        pct = 100.0 * done / total if total else 0.0
        self._draw_progress(pct)
        if hasattr(self, "lbl_prog"):
            if len(trs) == 1:
                t = trs[0]
                eta = (t["size"] - t["sent"]) / speed if speed > 0 else None
                arrow = "Приём" if t["dir"] == "in" else "Отправка"
                self.lbl_prog.config(
                    text=f"{arrow} {t['name'][-48:]} · {pct:.0f}% · "
                         f"{self._fmt_size(speed)}/с · {self._fmt_eta(eta)}")
            else:
                self.lbl_prog.config(
                    text=f"передач: {len(trs)} · {pct:.0f}% · {self._fmt_size(speed)}/с")
            self.lbl_prog.grid()
        if hasattr(self, "btn_cancel"):
            self.btn_cancel.config(state="normal")

    # --- Блок 2.9. История передач ----------------------------------------

    def _refresh_history(self):
        if not hasattr(self, "hist_tree"):
            return
        self.hist_tree.delete(*self.hist_tree.get_children())
        with self.lock:
            items = list(reversed(self.history))
        self._hist_rows = items
        dirs = {"in": "Принят", "out": "Отправлен"}
        states = {"ok": "Готово", "error": "Ошибка", "cancel": "Отменено",
                  "reject": "Отказ"}
        for i, r in enumerate(items):
            self.hist_tree.insert(
                "", "end", iid=str(i),
                tags=tuple(t for t in (
                    "even" if i % 2 else "odd",
                    {"error": "bad", "cancel": "dim", "reject": "dim"}.get(
                        r.get("status"))) if t),
                values=(r.get("ts", ""), dirs.get(r.get("dir"), r.get("dir", "")),
                        r.get("name", ""), r.get("peer", ""),
                        self._fmt_size(r.get("size")),
                        states.get(r.get("status"), r.get("status", ""))))

    def _open_history_path(self):
        if not hasattr(self, "hist_tree"):
            return
        sel = self.hist_tree.selection()
        if not sel:
            return
        try:
            rec = self._hist_rows[int(sel[0])]
        except (ValueError, IndexError):
            return
        path = rec.get("path") or ""
        target = path if os.path.isdir(path) else os.path.dirname(path)
        if not target or not os.path.isdir(target):
            target = self.download_dir
        self._open_folder(target)

    def _open_folder(self, target):
        try:
            if os.name == "nt":
                os.startfile(target)
            else:
                import subprocess
                import sys
                subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", target])
        except Exception as e:
            self._log(f"Не удалось открыть папку: {e}")

    def _open_downloads(self):
        os.makedirs(self.download_dir, exist_ok=True)
        self._open_folder(self.download_dir)

    def _clear_history(self):
        if not messagebox.askyesno("LAN Share", "Очистить историю передач?"):
            return
        with self.lock:
            self.history = []
        try:
            os.remove(HISTORY_PATH)
        except OSError:
            pass
        self._refresh_history()
        self._log("История передач очищена.")

    # --- Блок 2.6. Журнал событий ----------------------------------------

    def _log(self, text):
        """Потокобезопасно: пишем в очередь, вставку делает главный поток."""
        self.ui.put(("log", (text,)))

    def _append_log(self, text):
        if not hasattr(self, "log"):
            return
        low = text.lower()
        if text.startswith("Чат"):
            tag = "chat"
        elif any(w in low for w in ("ошибк", "не удалось", "не доставлен",
                                    "неверн", "не найден")):
            tag = "err"
        elif any(w in low for w in ("внимание", "отклон", "отмен", "бан", "кикнут")):
            tag = "warn"
        elif any(w in low for w in ("запущен", "вошли", "принят", "получен",
                                    "скопирован", "добавлено")):
            tag = "ok"
        else:
            tag = "msg"
        entry = (datetime.now().strftime("%H:%M:%S"), text, tag)
        self._log_buf.append(entry)
        del self._log_buf[:-600]
        self._write_log(*entry)

    def _write_log(self, stamp, text, tag):
        self.log.config(state="normal")
        self.log.insert("end", f"{stamp}  ", "ts")
        self.log.insert("end", f"{text}\n", tag)
        if int(self.log.index("end-1c").split(".")[0]) > 600:   # не раздуваем журнал
            self.log.delete("1.0", "101.0")
        self.log.see("end")
        self.log.config(state="disabled")

    # --- Блок 2.7. Настройки: папка загрузок, приём, SHA-256 --------------

    def _choose_dir(self):
        d = filedialog.askdirectory(title="Куда сохранять принятые файлы")
        if d:
            self.download_dir = d
            if hasattr(self, "ent_dir"):
                self.ent_dir.delete(0, "end")
                self.ent_dir.insert(0, d)
            self._save_config()

    def _set_opt(self, key, raw):
        """Сохранить одну настройку (с проверкой диапазона) и применить её сразу."""
        val = self._clean_opt(key, raw)
        if val is None or val == self.opts.get(key):
            return
        self.opts[key] = val
        self._save_config()
        self._opts_applied(key)

    def _opts_applied(self, key):
        """Что нужно обновить в окне после смены настройки."""
        try:
            if key == "device_name":
                self.lbl_me.config(
                    text=f"Этот ПК: {self.my_name()} · {self.my_ip} · порт {self.tcp_port}")
            elif key == "inbox_ttl":
                self._ib_hint.config(
                    text=f"Файл без ответа отклоняется через {self.opts['inbox_ttl']} с. "
                         f"Enter — принять, Delete — отклонить, Ctrl+A — выбрать все. "
                         f"Для текста «Принять» копирует его в буфер обмена.")
            elif key == "mute_min":
                self._btn_mute.config(text=f"Игнор {self.opts['mute_min']} мин")
        except (AttributeError, tk.TclError):
            pass

    def _apply_name(self):
        self._set_opt("device_name", self.ent_name.get())

    def _on_font_size(self, _e=None):
        # перестройка окна — не внутри обработчика самого выпадающего списка
        self.root.after(60, self._rebuild_ui)

    def _reset_opts(self):
        if not messagebox.askyesno("LAN Share", "Сбросить настройки на значения по умолчанию?\n"
                                   "Папка загрузок, баны и избранное не изменятся."):
            return
        self.opts = dict(DEFAULT_OPTS)
        self._save_config()
        self._log("Настройки сброшены. Порт TCP изменится после перезапуска.")
        self.root.after(60, self._rebuild_ui)

    def _apply_dir_entry(self):
        """Папка, введённая вручную в поле, тоже сохраняется."""
        d = self.ent_dir.get().strip()
        if d and d != self.download_dir:
            self.download_dir = d
            self._save_config()
            self._log(f"Папка для принятых файлов: {d}")

    def _set_receive_mode(self):
        modes = {"принимать автоматически": "auto", "спрашивать": "ask",
                 "отклонять": "reject"}
        self.receive_mode = modes.get(self.cmb_receive.get(), "ask")
        self._save_config()
        self._log(f"Режим приёма файлов: {self.cmb_receive.get()}")

    def _set_verify_hash(self):
        self.verify_hash = bool(self.var_hash.get())
        self._save_config()

    # --- Блок 2.8. Закрытие программы -------------------------------------

    def _on_close(self):
        self.alive = False
        try:
            self._apply_dir_entry()
        except Exception:
            pass
        for iid in list(self.inbox):          # не оставляем потоки ждать ответа
            try:
                self._inbox_resolve(iid, False)
            except Exception:
                pass
        if getattr(self, "_poll_id", None):
            try:
                self.root.after_cancel(self._poll_id)
            except Exception:
                pass
            self._poll_id = None
        if self._toast_job:
            try:
                self.root.after_cancel(self._toast_job)
            except Exception:
                pass
            self._toast_job = None
        with self.lock:
            for tr in self.transfers.values():
                tr["cancel"].set()
            for m in list(self.members.values()):
                try:
                    m["sock"].close()
                except OSError:
                    pass
        try:
            self._save_config()
        except Exception:
            pass
        try:
            self.tcp_sock.close()
        except OSError:
            pass
        try:
            self.udp_sock.close()
        except OSError:
            pass
        self.root.after(150, self.root.destroy)


def main():
    App().root.mainloop()


if __name__ == "__main__":
    main()
