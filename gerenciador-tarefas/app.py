#!/usr/bin/env python3
"""
python app.py
http://127.0.0.1:8000/

"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import secrets
import sqlite3
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone, date
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

# Módulo de autenticação/gestão de supervisores
import login  # login.py no mesmo diretório

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
DB_PATH = BASE_DIR / "tasks.db"
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")

# Sessões em memória (dev/demo)
SESSIONS: Dict[str, Dict[str, Any]] = {}
SESS_LOCK = threading.Lock()

PRIORITIES = {"alta", "media", "baixa"}

SECTORS = [
    ("marketing", "Marketing"),
    ("vendas", "Vendas"),
    ("compras", "Compras"),
    ("estoque", "Estoque"),
    ("juridico", "Jurídico"),
    ("ti", "TI"),
]
SECTOR_LABEL_BY_CODE = {c: l for c, l in SECTORS}
SECTOR_CODES = set(SECTOR_LABEL_BY_CODE)

STATUS_SAVED = {"em_andamento", "concluida"}
STATUS_FILTER_ALLOWED = {"em_andamento", "concluida", "atrasada"}

# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------
@dataclass
class Task:
    id: int
    title: str
    description: Optional[str]
    sector_code: str
    sector_label: str
    priority: str
    responsavel: str
    due_date: Optional[str]  # YYYY-MM-DD
    status_raw: str          # em_andamento|concluida
    status: str              # em_andamento|concluida|atrasada (derivado)
    created_at: str
    updated_at: Optional[str]

    def to_public(self) -> Dict[str, Any]:
        d = asdict(self)
        # compat com versões antigas do front
        d["sector"] = self.sector_label
        return d

# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        # tabela já na versão nova
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                sector TEXT NOT NULL,
                priority TEXT NOT NULL CHECK (priority IN ('alta','media','baixa')),
                responsavel TEXT NOT NULL,
                due_date TEXT, -- YYYY-MM-DD
                status TEXT NOT NULL DEFAULT 'em_andamento' CHECK (status IN ('em_andamento','concluida')),
                created_at TEXT NOT NULL,
                updated_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                action TEXT NOT NULL,
                username TEXT,
                role TEXT,
                ip TEXT,
                user_agent TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                action TEXT NOT NULL, -- create|update|delete
                task_id INTEGER,
                username TEXT,
                role TEXT,
                details_json TEXT
            )
            """
        )
        # Tabela de supervisores (hash de senha)
        login.init_users_schema(conn)
        conn.commit()


def migrate_db() -> None:
    """Adiciona colunas due_date/status se o banco for de versão antiga."""
    with get_conn() as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(tasks)")}
        changed = False
        if "due_date" not in cols:
            conn.execute("ALTER TABLE tasks ADD COLUMN due_date TEXT")
            changed = True
        if "status" not in cols:
            conn.execute("ALTER TABLE tasks ADD COLUMN status TEXT DEFAULT 'em_andamento'")
            changed = True
        if changed:
            conn.commit()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_priority(v: Optional[str]) -> Optional[str]:
    if not v: return None
    m = {
        "alta": "alta", "alto": "alta", "high": "alta",
        "média": "media", "media": "media", "medio": "media", "medium": "media",
        "baixa": "baixa", "baixo": "baixa", "low": "baixa",
    }
    return m.get(str(v).strip().lower())


def strip_accents(s: str) -> str:
    import unicodedata as _u
    return "".join(c for c in _u.normalize("NFD", s) if _u.category(c) != "Mn")


def normalize_sector(s: Optional[str]) -> Optional[str]:
    if not s: return None
    base = strip_accents(str(s)).strip().lower()
    aliases = {
        "marketing": "marketing", "vendas": "vendas", "compras": "compras",
        "estoque": "estoque", "juridico": "juridico", "ti": "ti",
        "tecnologia": "ti", "tecnologia da informacao": "ti",
    }
    return aliases.get(base)


def normalize_status(v: Optional[str]) -> Optional[str]:
    if not v: return None
    base = strip_accents(str(v)).strip().lower()
    aliases = {
        "em andamento": "em_andamento", "andamento": "em_andamento", "em_andamento": "em_andamento",
        "concluida": "concluida", "concluída": "concluida", "concluido": "concluida", "concluído": "concluida",
        # "atrasada" não é salvo; é um estado derivado
    }
    return aliases.get(base)


def today_str_utc() -> str:
    return date.today().isoformat()  # ISO YYYY-MM-DD (sem TZ)


def compute_status(due_date: Optional[str], raw_status: str) -> str:
    if raw_status != "concluida" and due_date:
        try:
            if due_date < today_str_utc():
                return "atrasada"
        except Exception:
            pass
    return raw_status


def code_to_label(code: str) -> str:
    return SECTOR_LABEL_BY_CODE.get(code, code.title())


def row_to_task(r: sqlite3.Row) -> Task:
    code = r["sector"]
    raw = (r["status"] or "em_andamento")
    due = r["due_date"]
    return Task(
        id=r["id"],
        title=r["title"],
        description=r["description"],
        sector_code=code,
        sector_label=code_to_label(code),
        priority=r["priority"],
        responsavel=r["responsavel"] or "",
        due_date=due,
        status_raw=raw,
        status=compute_status(due, raw),
        created_at=r["created_at"],
        updated_at=r["updated_at"],
    )


def build_where(
    q: str,
    sector_code: Optional[str],
    priority: Optional[str],
    status_filter: Optional[str],
    created_from: Optional[str],
    created_to: Optional[str],
    due_from: Optional[str],
    due_to: Optional[str],
) -> Tuple[str, List[Any]]:
    clauses: List[str] = []
    params: List[Any] = []

    if q:
        clauses.append("(title LIKE ? OR description LIKE ? OR responsavel LIKE ?)")
        like = f"%{q}%"; params.extend([like, like, like])
    if sector_code:
        clauses.append("sector = ?"); params.append(sector_code)
    if priority:
        clauses.append("priority = ?"); params.append(priority)
    if status_filter:
        if status_filter == "atrasada":
            clauses.append("(COALESCE(status,'em_andamento') != 'concluida' AND due_date IS NOT NULL AND due_date < DATE('now'))")
        elif status_filter in {"em_andamento", "concluida"}:
            clauses.append("COALESCE(status,'em_andamento') = ?"); params.append(status_filter)
    if created_from:
        clauses.append("DATE(created_at) >= ?"); params.append(created_from)
    if created_to:
        clauses.append("DATE(created_at) <= ?"); params.append(created_to)
    if due_from:
        clauses.append("due_date >= ?"); params.append(due_from)
    if due_to:
        clauses.append("due_date <= ?"); params.append(due_to)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params

# ---------------------------------------------------------------------------
# Logging de acesso/auditoria
# ---------------------------------------------------------------------------

def record_access(action: str, username: Optional[str], role: Optional[str], ip: Optional[str], user_agent: Optional[str]) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO access_log (ts, action, username, role, ip, user_agent) VALUES (?,?,?,?,?,?)",
            [utc_now_iso(), action, username, role, ip, user_agent],
        )
        conn.commit()


def record_audit(action: str, task_id: Optional[int], username: Optional[str], role: Optional[str], details: Dict[str, Any]) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_log (ts, action, task_id, username, role, details_json) VALUES (?,?,?,?,?,?)",
            [utc_now_iso(), action, task_id, username, role, json.dumps(details, ensure_ascii=False)],
        )
        conn.commit()

# ---------------------------------------------------------------------------
# Servidor
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "TaskHTTP/1.4"

    # ---------------- util ----------------
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: N802
        print("[INFO]", self.address_string(), "-", fmt % args)

    def _send_json(self, status: int, data: Any) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: int, text: str, content_type: str = "text/plain; charset=utf-8") -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, content_type: str = "text/html; charset=utf-8") -> None:
        if not path.exists() or not path.is_file():
            self._send_text(HTTPStatus.NOT_FOUND, "Arquivo não encontrado")
            return
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_csv(self, filename: str, rows: List[Dict[str, Any]], header: List[str]) -> None:
        buf = io.StringIO(); writer = csv.DictWriter(buf, fieldnames=header)
        writer.writeheader(); [writer.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in header}) for r in rows]
        data = buf.getvalue().encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f"attachment; filename={filename}")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location: str, status: int = HTTPStatus.SEE_OTHER) -> None:
        self.send_response(status); self.send_header("Location", location); self.end_headers()

    def _parse_cookies(self) -> Dict[str, str]:
        cookie = SimpleCookie(self.headers.get("Cookie")); return {k: m.value for k, m in cookie.items()}

    def _get_session(self) -> Dict[str, Any]:
        sid = self._parse_cookies().get("sid");
        if not sid: return {}
        with SESS_LOCK:
            return SESSIONS.get(sid, {})

    def _set_session(self, data: Dict[str, Any]) -> None:
        sid = secrets.token_urlsafe(24)
        with SESS_LOCK:
            SESSIONS[sid] = data
        self.send_header("Set-Cookie", f"sid={sid}; Path=/; HttpOnly; SameSite=Lax")

    def _clear_session(self) -> None:
        sid = self._parse_cookies().get("sid")
        if sid:
            with SESS_LOCK:
                SESSIONS.pop(sid, None)
            self.send_header("Set-Cookie", "sid=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax")

    def _require_login(self) -> Optional[Dict[str, Any]]:
        sess = self._get_session()
        if not sess.get("role"):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Não autenticado. Faça login."}); return None
        return sess

    def _require_admin(self) -> Optional[Dict[str, Any]]:
        sess = self._require_login();
        if not sess: return None
        if sess.get("role") != "admin":
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Permissão negada: requer admin."}); return None
        return sess

    def _require_admin_or_supervisor(self) -> Optional[Dict[str, Any]]:
        sess = self._require_login();
        if not sess: return None
        if sess.get("role") not in {"admin", "supervisor"}:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Requer admin ou supervisor."}); return None
        return sess

    def _read_json(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0")); raw = self.rfile.read(length) if length > 0 else b""
            return json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            return {}

    def _query_params(self) -> Dict[str, List[str]]:
        return parse_qs(urlparse(self.path).query)

    # ---------------- rotas ----------------
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/":
            sess = self._get_session(); return self._redirect("/app" if sess.get("role") else "/login")
        if path == "/app":
            sess = self._get_session()
            if not sess.get("role"):
                return self._redirect("/login?" + urlencode({"next": "/app"}))
            return self._send_file(TEMPLATES_DIR / "index.html")
        if path == "/login":
            return self._send_file(TEMPLATES_DIR / "login.html")
        if path == "/logout":
            sess = self._get_session(); self.send_response(HTTPStatus.SEE_OTHER)
            record_access("logout", sess.get("username"), sess.get("role"), self.client_address[0], self.headers.get("User-Agent"))
            self._clear_session(); self.send_header("Location", "/login"); self.end_headers(); return

        if path.startswith("/static/"):
            file_path = STATIC_DIR / path[len("/static/"):]
            ctype = "application/octet-stream"
            if str(file_path).endswith(".css"): ctype = "text/css; charset=utf-8"
            elif str(file_path).endswith(".js"): ctype = "application/javascript; charset=utf-8"
            elif str(file_path).endswith(".png"): ctype = "image/png"
            elif str(file_path).endswith(".svg"): ctype = "image/svg+xml"
            return self._send_file(file_path, ctype)

        # APIs comuns
        if path == "/api/me":
            sess = self._get_session(); role = sess.get("role") or "guest"; username = sess.get("username")
            return self._send_json(HTTPStatus.OK, {"role": role, "username": username})
        if path == "/api/sectors":
            return self._send_json(HTTPStatus.OK, [{"code": c, "label": l} for c, l in SECTORS])
        if path == "/api/tasks":
            return self._api_list_tasks()
        if path == "/api/tasks/recent":
            return self._api_recent_tasks()
        if path == "/api/stats/sector":
            return self._api_stats_sector()

        # APIs admin
        if path == "/api/admin/metrics":
            if not self._require_admin(): return
            return self._api_admin_metrics()
        if path == "/api/admin/accesses":
            if not self._require_admin(): return
            return self._api_admin_accesses()
        if path == "/api/admin/audits":
            if not self._require_admin(): return
            return self._api_admin_audits()
        if path == "/api/admin/export":
            if not self._require_admin(): return
            return self._api_admin_export()
        # Gestão de supervisores (somente admin)
        if path == "/api/admin/supervisors":
            if not self._require_admin(): return
            return self._api_admin_list_supervisors()

        self._send_text(HTTPStatus.NOT_FOUND, "Não encontrado")

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/login":
            length = int(self.headers.get("Content-Length", "0")); raw = self.rfile.read(length) if length > 0 else b""; data = parse_qs(raw.decode("utf-8")) if raw else {}
            action = (data.get("action", [""])[0] or "").lower()
            if action == "guest":
                self.send_response(HTTPStatus.SEE_OTHER)
                self._set_session({"role": "guest", "username": "Usuário básico"})
                record_access("login_guest", "Usuário básico", "guest", self.client_address[0], self.headers.get("User-Agent"))
                nxt = data.get("next", ["/app"])[0]; self.send_header("Location", nxt if nxt.startswith("/") else "/app"); self.end_headers(); return
            if action == "admin":
                username = (data.get("username", [""])[0] or "").strip(); password = data.get("password", [""])[0]
                if login.authenticate_admin(username, password):
                    self.send_response(HTTPStatus.SEE_OTHER)
                    self._set_session({"role": "admin", "username": username})
                    record_access("login_admin", username, "admin", self.client_address[0], self.headers.get("User-Agent"))
                    nxt = data.get("next", ["/app"])[0]; self.send_header("Location", nxt if nxt.startswith("/") else "/app"); self.end_headers(); return
                self.send_response(HTTPStatus.UNAUTHORIZED); self.send_header("Content-Type", "text/html; charset=utf-8"); self.end_headers();
                self.wfile.write(b"<html><body><script>alert('Usuario ou senha invalidos');window.location='/login';</script></body></html>"); return
            if action == "supervisor":
                username = (data.get("username", [""])[0] or "").strip(); password = data.get("password", [""])[0]
                with get_conn() as conn:
                    ok = login.authenticate_supervisor(conn, username, password)
                if ok:
                    self.send_response(HTTPStatus.SEE_OTHER)
                    self._set_session({"role": "supervisor", "username": username})
                    record_access("login_supervisor", username, "supervisor", self.client_address[0], self.headers.get("User-Agent"))
                    nxt = data.get("next", ["/app"])[0]; self.send_header("Location", nxt if nxt.startswith("/") else "/app"); self.end_headers(); return
                self.send_response(HTTPStatus.UNAUTHORIZED); self.send_header("Content-Type", "text/html; charset=utf-8"); self.end_headers();
                self.wfile.write(b"<html><body><script>alert('Usuario ou senha invalidos');window.location='/login';</script></body></html>"); return
            return self._send_text(HTTPStatus.BAD_REQUEST, "Acao invalida")

        if path == "/api/tasks":
            if not self._require_login(): return
            sess = self._get_session(); payload = self._read_json()
            title = (payload.get("title") or "").strip(); description = (payload.get("description") or "").strip()
            sector_in = payload.get("sector") or payload.get("sector_code"); sector_code = normalize_sector(sector_in)
            priority = normalize_priority(payload.get("priority")); responsavel = (payload.get("responsavel") or "").strip()
            due_date = (payload.get("due_date") or "").strip() or None; status_in = normalize_status(payload.get("status") or "em_andamento") or "em_andamento"

            if not title: return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "T\u00edtulo \u00e9 obrigat\u00f3rio."})
            if not sector_code or sector_code not in SECTOR_CODES: return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Setor inv\u00e1lido."})
            if priority not in PRIORITIES: return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Prioridade deve ser alta, media ou baixa."})
            if not responsavel: return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Respons\u00e1vel \u00e9 obrigat\u00f3rio."})
            if due_date and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", due_date):
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "due_date deve ser YYYY-MM-DD."})
            if status_in not in STATUS_SAVED: return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Status deve ser em_andamento ou concluida."})

            now = utc_now_iso()
            with get_conn() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO tasks (title, description, sector, priority, responsavel, due_date, status, created_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    [title, description, sector_code, priority, responsavel, due_date, status_in, now],
                )
                task_id = cur.lastrowid; conn.commit()
            record_audit("create", task_id, sess.get("username"), sess.get("role"), {
                "title": title, "sector_code": sector_code, "priority": priority, "responsavel": responsavel,
                "due_date": due_date, "status": status_in,
            })
            return self._send_json(HTTPStatus.CREATED, {"ok": True, "id": task_id})

        # Criar supervisor (somente admin)
        if path == "/api/admin/supervisors":
            if not self._require_admin(): return
            payload = self._read_json(); username = (payload.get("username") or "").strip(); password = payload.get("password") or ""
            if not username or not password:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "username e password obrigatórios"})
            try:
                with get_conn() as conn:
                    login.create_supervisor(conn, username, password)
                return self._send_json(HTTPStatus.CREATED, {"ok": True})
            except Exception as e:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(e)})

        self._send_text(HTTPStatus.NOT_FOUND, "Não encontrado")

    def do_PUT(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        m = re.fullmatch(r"/api/tasks/(\d+)", path)
        if m:
            if not self._require_admin_or_supervisor(): return
            sess = self._get_session(); task_id = int(m.group(1)); payload = self._read_json()
            sets: List[str] = []; params: List[Any] = []; changes: Dict[str, Any] = {}

            if "title" in payload:
                title = (payload.get("title") or "").strip()
                if not title: return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "T\u00edtulo n\u00e3o pode ser vazio."})
                sets.append("title = ?"); params.append(title); changes["title"] = title
            if "description" in payload:
                description = (payload.get("description") or "").strip(); sets.append("description = ?"); params.append(description); changes["description"] = description
            if "sector" in payload or "sector_code" in payload:
                sector_code = normalize_sector(payload.get("sector") or payload.get("sector_code"))
                if not sector_code or sector_code not in SECTOR_CODES: return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Setor inv\u00e1lido."})
                sets.append("sector = ?"); params.append(sector_code); changes["sector_code"] = sector_code
            if "priority" in payload:
                pr = normalize_priority(payload.get("priority"))
                if pr not in PRIORITIES: return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Prioridade deve ser alta, media ou baixa."})
                sets.append("priority = ?"); params.append(pr); changes["priority"] = pr
            if "responsavel" in payload:
                resp = (payload.get("responsavel") or "").strip();
                if not resp: return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Respons\u00e1vel n\u00e3o pode ser vazio."})
                sets.append("responsavel = ?"); params.append(resp); changes["responsavel"] = resp
            if "due_date" in payload:
                dd = (payload.get("due_date") or "").strip() or None
                if dd and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", dd):
                    return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "due_date deve ser YYYY-MM-DD."})
                sets.append("due_date = ?"); params.append(dd); changes["due_date"] = dd
            if "status" in payload:
                st = normalize_status(payload.get("status"))
                if st not in STATUS_SAVED: return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Status deve ser em_andamento ou concluida."})
                sets.append("status = ?"); params.append(st); changes["status"] = st

            if not sets: return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Nenhum campo para atualizar."})

            sets.append("updated_at = ?"); params.append(utc_now_iso()); params.append(task_id)
            with get_conn() as conn:
                conn.execute(f"UPDATE tasks SET {', '.join(sets)} WHERE id = ?", params); conn.commit()
            record_audit("update", task_id, sess.get("username"), sess.get("role"), changes)
            return self._send_json(HTTPStatus.OK, {"ok": True})

        # Atualizar senha/estado de um supervisor (somente admin)
        m2 = re.fullmatch(r"/api/admin/supervisors/([a-zA-Z0-9_.-]{3,32})", path)
        if m2:
            if not self._require_admin(): return
            username = m2.group(1)
            payload = self._read_json()
            new_pass = payload.get("password")
            is_active = payload.get("is_active")
            try:
                with get_conn() as conn:
                    if new_pass is not None and str(new_pass).strip() != "":
                        login.set_supervisor_password(conn, username, str(new_pass))
                    if is_active is not None:
                        conn.execute("UPDATE supervisors SET is_active = ?, updated_at = ? WHERE username = ?", [1 if bool(is_active) else 0, utc_now_iso(), username])
                        conn.commit()
                return self._send_json(HTTPStatus.OK, {"ok": True})
            except Exception as e:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(e)})

        self._send_text(HTTPStatus.NOT_FOUND, "Não encontrado")

    def do_DELETE(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        m = re.fullmatch(r"/api/tasks/(\d+)", path)
        if m:
            if not self._require_admin_or_supervisor(): return
            sess = self._get_session(); task_id = int(m.group(1))
            with get_conn() as conn:
                conn.execute("DELETE FROM tasks WHERE id = ?", [task_id]); conn.commit()
            record_audit("delete", task_id, sess.get("username"), sess.get("role"), {})
            return self._send_json(HTTPStatus.OK, {"ok": True})

        m2 = re.fullmatch(r"/api/admin/supervisors/([a-zA-Z0-9_.-]{3,32})", path)
        if m2:
            if not self._require_admin(): return
            username = m2.group(1)
            try:
                with get_conn() as conn:
                    login.delete_supervisor(conn, username)
                return self._send_json(HTTPStatus.OK, {"ok": True})
            except Exception as e:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(e)})

        self._send_text(HTTPStatus.NOT_FOUND, "Não encontrado")

    # ---------- API handlers auxiliares ----------
    def _api_list_tasks(self) -> None:
        qs = self._query_params()
        q = (qs.get("q", [""])[0] or "").strip()
        sector_code = normalize_sector((qs.get("sector", [""])[0] or "").strip())
        priority = normalize_priority(qs.get("priority", [""])[0])
        status_filter = (qs.get("status", [""])[0] or "").strip().lower() or None
        if status_filter and status_filter not in STATUS_FILTER_ALLOWED: status_filter = None
        created_from = (qs.get("created_from", [""])[0] or "").strip() or None
        created_to = (qs.get("created_to", [""])[0] or "").strip() or None
        due_from = (qs.get("due_from", [""])[0] or "").strip() or None
        due_to = (qs.get("due_to", [""])[0] or "").strip() or None
        limit = int(qs.get("limit", ["100"])[0]); offset = int(qs.get("offset", ["0"])[0])
        sort_by = (qs.get("sort_by", ["created_at"])[0] or "created_at"); order = (qs.get("order", ["desc"])[0] or "desc").lower()
        if sort_by not in {"created_at", "updated_at", "priority", "sector", "title", "responsavel", "due_date", "status"}: sort_by = "created_at"
        if order not in {"asc", "desc"}: order = "desc"

        where, params = build_where(q, sector_code, priority, status_filter, created_from, created_to, due_from, due_to)

        if sort_by == "status":
            # Ordena com "atrasada" primeiro, depois em_andamento, depois concluida
            order_sql = "CASE WHEN (COALESCE(status,'em_andamento') != 'concluida' AND due_date < DATE('now')) THEN 0 WHEN COALESCE(status,'em_andamento')='em_andamento' THEN 1 ELSE 2 END"
            order_clause = f"ORDER BY {order_sql} {order.upper()}, created_at DESC"
        else:
            order_clause = f"ORDER BY {sort_by} {order.upper()}"

        sql = f"""
            SELECT id, title, description, sector, priority, responsavel, due_date, status, created_at, updated_at
            FROM tasks
            {where}
            {order_clause}
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with get_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        tasks = [row_to_task(r) for r in rows]
        return self._send_json(HTTPStatus.OK, [t.to_public() for t in tasks])

    def _api_recent_tasks(self) -> None:
        qs = self._query_params(); limit = int(qs.get("limit", ["5"])[0])
        with get_conn() as conn:
            rows = conn.execute(
                """
                SELECT id, title, description, sector, priority, responsavel, due_date, status, created_at, updated_at
                FROM tasks
                ORDER BY created_at DESC
                LIMIT ?
                """,
                [limit],
            ).fetchall()
        tasks = [row_to_task(r) for r in rows]
        return self._send_json(HTTPStatus.OK, [t.to_public() for t in tasks])

    def _api_stats_sector(self) -> None:
        with get_conn() as conn:
            rows = conn.execute(
                """
                SELECT COALESCE(sector, 'sem_setor') AS sector, COUNT(*) AS total
                FROM tasks
                GROUP BY COALESCE(sector, 'sem_setor')
                ORDER BY total DESC
                """
            ).fetchall()
        data = []
        for r in rows:
            code = r["sector"]; label = code_to_label(code) if code != "sem_setor" else "Sem Setor"
            data.append({"sector": label, "sector_code": code, "sector_label": label, "total": r["total"]})
        return self._send_json(HTTPStatus.OK, data)

    # ---------- ADMIN ----------
    def _api_admin_metrics(self) -> None:
        with get_conn() as conn:
            total_accesses = int(conn.execute("SELECT COUNT(*) FROM access_log").fetchone()[0])
            total_audits = int(conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])
            sups_total = int(conn.execute("SELECT COUNT(*) FROM supervisors").fetchone()[0])
        with SESS_LOCK:
            roles = [v.get("role") for v in SESSIONS.values()]
            sup_online = [v.get("username") for v in SESSIONS.values() if v.get("role") == "supervisor" and v.get("username")]
        active_sessions = {
            "total": len(roles),
            "admin": sum(1 for r in roles if r == "admin"),
            "supervisor": sum(1 for r in roles if r == "supervisor"),
            "guest": sum(1 for r in roles if r == "guest"),
        }
        # "senhas ativas": 1 do admin + qtd de supervisores ativos
        with get_conn() as conn:
            sup_active = int(conn.execute("SELECT COUNT(*) FROM supervisors WHERE is_active = 1").fetchone()[0])
        metrics = {
            "total_accesses": total_accesses,
            "total_changes": total_audits,
            "active_sessions": active_sessions,
            "senhas_ativas": 1 + sup_active,
            "supervisores_total": sups_total,
            "supervisores_online": len(set(sup_online)),
        }
        return self._send_json(HTTPStatus.OK, metrics)

    def _api_admin_accesses(self) -> None:
        qs = self._query_params(); limit = int(qs.get("limit", ["100"])[0])
        with get_conn() as conn:
            rows = conn.execute("SELECT ts, action, username, role, ip, user_agent FROM access_log ORDER BY ts DESC LIMIT ?", [limit]).fetchall()
        return self._send_json(HTTPStatus.OK, [dict(r) for r in rows])

    def _api_admin_audits(self) -> None:
        qs = self._query_params(); limit = int(qs.get("limit", ["100"])[0])
        with get_conn() as conn:
            rows = conn.execute("SELECT ts, action, task_id, username, role, details_json FROM audit_log ORDER BY ts DESC LIMIT ?", [limit]).fetchall()
        data: List[Dict[str, Any]] = []
        for r in rows:
            try:
                details = json.loads(r["details_json"]) if r["details_json"] else {}
            except Exception:
                details = {}
            data.append({"ts": r["ts"], "action": r["action"], "task_id": r["task_id"], "username": r["username"], "role": r["role"], "details": details})
        return self._send_json(HTTPStatus.OK, data)

    def _api_admin_export(self) -> None:
        qs = self._query_params(); typ = (qs.get("type", [""])[0] or "").lower()
        if typ in {"access", "accesses"}:
            with get_conn() as conn:
                rows = conn.execute("SELECT ts, action, username, role, ip, user_agent FROM access_log ORDER BY ts DESC").fetchall()
            return self._send_csv("accesses.csv", [dict(r) for r in rows], ["ts", "action", "username", "role", "ip", "user_agent"])
        if typ in {"audit", "audits"}:
            with get_conn() as conn:
                rows = conn.execute("SELECT ts, action, task_id, username, role, details_json FROM audit_log ORDER BY ts DESC").fetchall()
            data = [{"ts": r["ts"], "action": r["action"], "task_id": r["task_id"], "username": r["username"], "role": r["role"], "details_json": r["details_json"]} for r in rows]
            return self._send_csv("audits.csv", data, ["ts", "action", "task_id", "username", "role", "details_json"])
        return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "type deve ser access|audit"})

    def _api_admin_list_supervisors(self) -> None:
        with SESS_LOCK:
            online = set(login.usernames_online_from_sessions(SESSIONS))
        with get_conn() as conn:
            sups = login.list_supervisors(conn, active_usernames=online)
        return self._send_json(HTTPStatus.OK, [s.to_public() for s in sups])

# ---------------------------------------------------------------------------
# Seed (15 tarefas)
# ---------------------------------------------------------------------------

def seed_mock_data() -> None:
    with get_conn() as conn:
        cur = conn.execute("SELECT COUNT(*) FROM tasks"); count = int(cur.fetchone()[0])
        if count > 0: return
        now = datetime.now(timezone.utc)
        # (title, desc, sector, priority, responsavel, due_offset_days, status)
        items = [
            ("Revisar campanha Dia das Mães", "Ajustar artes e CTA.", "marketing", "alta", "Ana Souza",  2,  "em_andamento"),
            ("Prospectar leads semanais", "Meta: 50 novos leads.", "vendas",   "media", "Carlos Lima",  7,  "em_andamento"),
            ("Cotação de fornecedores", "Papel A4, canetas, pastas.", "compras",  "baixa", "Mariana Alves", -1,  "em_andamento"),  # atrasada
            ("Inventário trimestral", "Seção A-B.", "estoque", "media", "João Pedro", 5,  "em_andamento"),
            ("Revisar contrato de parceria", "Cláusula 4.2.", "juridico", "alta", "Dra. Paula", -2,  "concluida"),
            ("Atualizar servidor de e-mail", "Janela às 22h.", "ti", "alta", "Rafael Silva", 0,  "em_andamento"),
            ("Calendário de postagens", "Próximas 4 semanas.", "marketing", "baixa", "Beatriz Rocha", 14, "em_andamento"),
            ("Follow-up propostas", "XPTO, Alfa.", "vendas", "alta", "Renato Costa", -3, "em_andamento"),  # atrasada
            ("Pedido de EPI", "Luvas e máscaras.", "compras", "media", "Sofia Matos", 10, "em_andamento"),
            ("Conferir entrada de mercadorias", "NF 34567.", "estoque", "alta", "Diego Nunes", -5, "concluida"),
            ("Parecer sobre LGPD", "Coleta no site.", "juridico", "media", "Dr. Henrique", 3, "em_andamento"),
            ("Backup mensal", "Cold storage.", "ti", "baixa", "Camila Dias", -1, "concluida"),
            ("Briefing campanha inverno", "Definir público.", "marketing", "media", "Fernanda Melo", 9, "em_andamento"),
            ("Treinamento de produto", "Equipe regional.", "vendas", "baixa", "Gustavo Freitas", 1, "em_andamento"),
            ("Organizar prateleiras setor C", "Reetiquetar caixas.", "estoque", "media", "Larissa Prado", -4, "em_andamento"),  # atrasada
        ]
        for i, (title, desc, sector, prio, resp, due_off, st) in enumerate(items):
            created = (now - timedelta(hours=48 - i*2)).isoformat()
            due = (date.today() + timedelta(days=due_off)).isoformat()
            conn.execute(
                "INSERT INTO tasks (title, description, sector, priority, responsavel, due_date, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
                [title, desc, sector, prio, resp, due, st, created],
            )
        conn.commit()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db(); migrate_db(); seed_mock_data()
    # Seed opcional de supervisores (descomente se quiser usuários de teste)
    # with get_conn() as _c: login.seed_supervisors(_c)

    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Servidor rodando em http://{HOST}:{PORT} — CTRL+C para parar")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrando...")
        httpd.server_close()
