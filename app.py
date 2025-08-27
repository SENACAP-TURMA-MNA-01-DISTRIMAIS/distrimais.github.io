# app.py — versão Flask pronta para Render
from __future__ import annotations

import os
import json
import csv
import secrets
import hashlib
from datetime import datetime, date, timedelta, timezone
from functools import wraps

from flask import (
    Flask, request, jsonify, render_template, redirect,
    url_for, session, abort, make_response
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, text

# -----------------------------------------------------------------------------
# Configuração
# -----------------------------------------------------------------------------
def utcnow():
    return datetime.now(timezone.utc)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///tasks.db")
SECRET_KEY   = os.getenv("SECRET_KEY", "dev-secret-123")

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = SECRET_KEY
app.config["JSON_AS_ASCII"] = False

db = SQLAlchemy(app)

# -----------------------------------------------------------------------------
# Modelos
# -----------------------------------------------------------------------------
class Task(db.Model):
    __tablename__ = "tasks"
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    sector_code = db.Column(db.String(32), nullable=False)
    priority    = db.Column(db.String(16), nullable=False)        # alta, media, baixa
    status      = db.Column(db.String(20), nullable=False)        # em_andamento, concluida, atrasada
    responsavel = db.Column(db.String(100), nullable=False)
    due_date    = db.Column(db.Date, nullable=False)
    created_at  = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at  = db.Column(db.DateTime(timezone=True))

class Supervisor(db.Model):
    __tablename__ = "supervisors"
    username   = db.Column(db.String(64), primary_key=True)
    pass_hash  = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True))
    is_active  = db.Column(db.Boolean, nullable=False, default=True)

class AccessLog(db.Model):
    __tablename__ = "access_logs"
    id        = db.Column(db.Integer, primary_key=True)
    ts        = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    action    = db.Column(db.String(40), nullable=False)  # login/logout
    role      = db.Column(db.String(20), nullable=False)
    username  = db.Column(db.String(80))
    ip        = db.Column(db.String(80))
    user_agent= db.Column(db.Text)

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id        = db.Column(db.Integer, primary_key=True)
    ts        = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    action    = db.Column(db.String(40), nullable=False)          # task_create/update/delete
    task_id   = db.Column(db.Integer)
    role      = db.Column(db.String(20), nullable=False)
    username  = db.Column(db.String(80))
    details   = db.Column(db.Text)  # JSON serializado

class ActiveSession(db.Model):
    __tablename__ = "active_sessions"
    sid       = db.Column(db.String(64), primary_key=True)
    role      = db.Column(db.String(20), nullable=False)
    username  = db.Column(db.String(80))
    last_seen = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

# -----------------------------------------------------------------------------
# Constantes / util
# -----------------------------------------------------------------------------
SECTORS = [
    {"code": "marketing", "label": "Marketing"},
    {"code": "vendas",    "label": "Vendas"},
    {"code": "compras",   "label": "Compras"},
    {"code": "estoque",   "label": "Estoque"},
    {"code": "juridico",  "label": "Jurídico"},
    {"code": "ti",        "label": "TI"},
]
SECTOR_MAP = {s["code"]: s["label"] for s in SECTORS}

def sector_label(code: str) -> str:
    return SECTOR_MAP.get(code, code)

# Password hashing (compatível com PBKDF2 usado antes)
_PBKDF2_ALGO = "sha256"
_PBKDF2_ITERS = int(os.getenv("PBKDF2_ITERS", "200000"))
_PBKDF2_SALT_BYTES = 16

def _gen_salt(n: int = _PBKDF2_SALT_BYTES) -> bytes:
    return secrets.token_bytes(n)

def _pbkdf2_hash(password: str, salt: bytes, iters: int = _PBKDF2_ITERS) -> bytes:
    return hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode("utf-8"), salt, iters)

def hash_password(password: str) -> str:
    salt = _gen_salt()
    h = _pbkdf2_hash(password, salt)
    return f"pbkdf2_sha256${_PBKDF2_ITERS}${salt.hex()}${h.hex()}"

def verify_password(stored: str, password: str) -> bool:
    try:
        scheme, iters_s, salt_hex, hash_hex = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        iters = int(iters_s)
        salt = bytes.fromhex(salt_hex)
        expect = bytes.fromhex(hash_hex)
        calc = _pbkdf2_hash(password, salt, iters)
        return secrets.compare_digest(calc, expect)
    except Exception:
        return False

def current_role() -> str:
    return session.get("role", "guest")

def current_username() -> str | None:
    return session.get("username")

def require_roles(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if current_role() not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco

def log_access(action: str):
    try:
        db.session.add(AccessLog(
            action=action, role=current_role(), username=current_username(),
            ip=request.headers.get("X-Forwarded-For", request.remote_addr),
            user_agent=request.headers.get("User-Agent")
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()

def log_audit(action: str, task_id: int | None, details: dict | None):
    try:
        db.session.add(AuditLog(
            action=action, task_id=task_id,
            role=current_role(), username=current_username(),
            details=json.dumps(details or {}, ensure_ascii=False)
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()

# -----------------------------------------------------------------------------
# Hooks de request: manter sessões ativas
# -----------------------------------------------------------------------------
@app.before_request
def _touch_session():
    # cria sid próprio se não houver (usado para ActiveSession)
    if "sid" not in session:
        session["sid"] = secrets.token_hex(16)
        session.modified = True
    # atualiza sessão ativa
    try:
        sid = session["sid"]
        role = current_role()
        username = current_username()
        now = utcnow()
        row = ActiveSession.query.get(sid)
        if row is None:
            db.session.add(ActiveSession(sid=sid, role=role, username=username, last_seen=now))
        else:
            row.role = role
            row.username = username
            row.last_seen = now
        db.session.commit()
    except Exception:
        db.session.rollback()

# limpa sessões antigas de tempos em tempos (opcional)
@app.after_request
def _cleanup(resp):
    try:
        cutoff = utcnow() - timedelta(minutes=30)
        db.session.query(ActiveSession).filter(ActiveSession.last_seen < cutoff).delete()
        db.session.commit()
    except Exception:
        db.session.rollback()
    return resp

# -----------------------------------------------------------------------------
# Rotas de páginas
# -----------------------------------------------------------------------------
@app.route("/")
def root():
    # se não logado, manda pro login
    if "role" not in session:
        return redirect(url_for("login"))
    return render_template("index.html")

# >>> ADICIONE ESTE BLOCO AQUI <<<
@app.route("/app")
def app_alias():
    # garante que só entra logado; mantém ?next=/app se não estiver logado
    if "role" not in session:
        return redirect(url_for("login", next="/app"))
    return render_template("index.html")
# <<< FIM DO BLOCO >>>

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    # POST
    action = request.form.get("action")
    next_url = request.form.get("next") or url_for("root")

    if action == "guest":
        session.clear()
        session["role"] = "guest"
        session["username"] = None
        log_access("login")
        return redirect(next_url)

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if action == "admin":
        if secrets.compare_digest(username, ADMIN_USER) and secrets.compare_digest(password, ADMIN_PASS):
            session.clear()
            session["role"] = "admin"
            session["username"] = username
            log_access("login")
            return redirect(next_url)
        return render_template("login.html", error="Admin inválido"), 401

    if action == "supervisor":
        sup = Supervisor.query.filter_by(username=username, is_active=True).first()
        if sup and verify_password(sup.pass_hash, password):
            session.clear()
            session["role"] = "supervisor"
            session["username"] = username
            log_access("login")
            return redirect(next_url)
        return render_template("login.html", error="Supervisor inválido"), 401

    return render_template("login.html", error="Ação inválida"), 400

@app.route("/logout")
def logout():
    log_access("logout")
    session.clear()
    return redirect(url_for("login"))

# -----------------------------------------------------------------------------
# APIs públicas para o front
# -----------------------------------------------------------------------------
@app.route("/api/me")
def api_me():
    return jsonify({
        "role": current_role(),
        "username": current_username()
    })

@app.route("/api/sectors")
def api_sectors():
    return jsonify(SECTORS)

@app.route("/api/tasks", methods=["GET", "POST"])
def api_tasks():
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        try:
            t = Task(
                title=data["title"].strip(),
                description=(data.get("description") or "").strip(),
                sector_code=data["sector_code"],
                priority=data["priority"],
                status=data.get("status") or "em_andamento",
                responsavel=(data.get("responsavel") or "").strip(),
                due_date=date.fromisoformat(data["due_date"]),
                created_at=utcnow(),
            )
            db.session.add(t)
            db.session.commit()
            log_audit("task_create", t.id, {"title": t.title})
            return jsonify({"ok": True, "id": t.id}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": f"Dados inválidos: {e}"}), 400

    # GET com filtros/paginação
    q = (request.args.get("q") or "").strip().lower()
    sector = request.args.get("sector")
    priority = request.args.get("priority")
    status = request.args.get("status")
    due_from = request.args.get("due_from")
    due_to   = request.args.get("due_to")
    limit  = max(1, min(int(request.args.get("limit", 20)), 100))
    offset = max(0, int(request.args.get("offset", 0)))

    query = Task.query
    if q:
        like = f"%{q}%"
        query = query.filter(
            db.or_(
                func.lower(Task.title).like(like),
                func.lower(Task.description).like(like),
                func.lower(Task.responsavel).like(like),
            )
        )
    if sector:
        query = query.filter(Task.sector_code == sector)
    if priority:
        query = query.filter(Task.priority == priority)
    if status:
        query = query.filter(Task.status == status)
    if due_from:
        try:
            df = date.fromisoformat(due_from)
            query = query.filter(Task.due_date >= df)
        except Exception:
            pass
    if due_to:
        try:
            dt_ = date.fromisoformat(due_to)
            query = query.filter(Task.due_date <= dt_)
        except Exception:
            pass

    rows = (query.order_by(Task.created_at.desc())
                 .limit(limit).offset(offset).all())

    def to_dict(t: Task):
        return {
            "id": t.id,
            "title": t.title,
            "description": t.description,
            "sector_code": t.sector_code,
            "sector_label": sector_label(t.sector_code),
            "priority": t.priority,
            "status": t.status,
            "responsavel": t.responsavel,
            "due_date": t.due_date.isoformat(),
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "updated_at": t.updated_at.isoformat() if t.updated_at else None,
        }

    return jsonify([to_dict(t) for t in rows])

@app.route("/api/tasks/<int:task_id>", methods=["PUT", "DELETE"])
@require_roles("admin", "supervisor")
def api_task_update_delete(task_id: int):
    t = Task.query.get_or_404(task_id)

    if request.method == "DELETE":
        db.session.delete(t)
        db.session.commit()
        log_audit("task_delete", task_id, {"title": t.title})
        return jsonify({"ok": True})

    data = request.get_json(force=True, silent=True) or {}
    changed = {}
    for field in ["title", "description", "priority", "status", "responsavel"]:
        if field in data:
            setattr(t, field, (data[field] or "").strip())
            changed[field] = data[field]
    if "sector_code" in data:
        t.sector_code = data["sector_code"]
        changed["sector_code"] = data["sector_code"]
    if "due_date" in data:
        try:
            t.due_date = date.fromisoformat(data["due_date"])
            changed["due_date"] = data["due_date"]
        except Exception:
            return jsonify({"error": "due_date inválida"}), 400

    t.updated_at = utcnow()
    db.session.commit()
    log_audit("task_update", task_id, changed)
    return jsonify({"ok": True})

@app.route("/api/tasks/recent")
def api_tasks_recent():
    limit = max(1, min(int(request.args.get("limit", 5)), 20))
    rows = Task.query.order_by(Task.created_at.desc()).limit(limit).all()
    return jsonify([
        {
            "id": t.id,
            "title": t.title,
            "description": t.description,
            "sector_code": t.sector_code,
            "sector_label": sector_label(t.sector_code),
            "priority": t.priority,
            "status": t.status,
            "responsavel": t.responsavel,
            "due_date": t.due_date.isoformat(),
            "created_at": t.created_at.isoformat() if t.created_at else None,
        }
        for t in rows
    ])

@app.route("/api/stats/sector")
def api_stats_sector():
    rows = db.session.query(Task.sector_code, func.count(Task.id))\
        .group_by(Task.sector_code).all()
    return jsonify([
        {"sector": code, "sector_label": sector_label(code), "total": int(total)}
        for code, total in rows
    ])

# -----------------------------------------------------------------------------
# Admin
# -----------------------------------------------------------------------------
@app.route("/api/admin/metrics")
@require_roles("admin")
def api_admin_metrics():
    total_accesses = AccessLog.query.count()
    total_changes  = AuditLog.query.count()

    # sessões ativas (vistas últimos 10 min)
    cutoff = utcnow() - timedelta(minutes=10)
    active = ActiveSession.query.filter(ActiveSession.last_seen >= cutoff).all()
    by_role = {"admin": 0, "supervisor": 0, "guest": 0}
    for s in active:
        if s.role in by_role:
            by_role[s.role] += 1
        else:
            by_role["guest"] += 1
    return jsonify({
        "total_accesses": total_accesses,
        "total_changes": total_changes,
        "active_sessions": {
            "total": len(active),
            "admin": by_role["admin"],
            "supervisor": by_role["supervisor"],
            "guest": by_role["guest"],
        },
        "senhas_ativas": Supervisor.query.filter_by(is_active=True).count(),
    })

@app.route("/api/admin/supervisors", methods=["GET", "POST"])
@require_roles("admin")
def api_supervisors():
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        if not username or not password:
            return jsonify({"error": "Informe usuário e senha"}), 400
        if Supervisor.query.get(username):
            return jsonify({"error": "Usuário já existe"}), 400
        sup = Supervisor(username=username, pass_hash=hash_password(password))
        db.session.add(sup)
        db.session.commit()
        return jsonify({"ok": True})

    rows = Supervisor.query.order_by(Supervisor.username.asc()).all()
    # considerar online = sessão ativa nos últimos 10 min
    cutoff = utcnow() - timedelta(minutes=10)
    online_set = {s.username for s in ActiveSession.query
                  .filter(ActiveSession.last_seen >= cutoff,
                          ActiveSession.role == "supervisor").all()}
    out = []
    for s in rows:
        out.append({
            "username": s.username,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "updated_at": s.updated_at.isoformat() if s.updated_at else None,
            "is_active": bool(s.is_active),
            "online": s.username in online_set
        })
    return jsonify(out)

@app.route("/api/admin/supervisors/<username>", methods=["PUT", "DELETE"])
@require_roles("admin")
def api_supervisor_update_delete(username: str):
    s = Supervisor.query.get_or_404(username)
    if request.method == "DELETE":
        db.session.delete(s)
        db.session.commit()
        return jsonify({"ok": True})

    data = request.get_json(force=True, silent=True) or {}
    changed = {}
    if "password" in data:
        s.pass_hash = hash_password(data["password"])
        s.updated_at = utcnow()
        changed["password"] = "***"
    if "is_active" in data:
        s.is_active = bool(data["is_active"])
        s.updated_at = utcnow()
        changed["is_active"] = s.is_active
    db.session.commit()
    return jsonify({"ok": True, "changed": changed})

@app.route("/api/admin/accesses")
@require_roles("admin")
def api_admin_accesses():
    limit = max(1, min(int(request.args.get("limit", 100)), 1000))
    rows = AccessLog.query.order_by(AccessLog.ts.desc()).limit(limit).all()
    return jsonify([
        {"ts": r.ts.isoformat(), "action": r.action, "role": r.role,
         "username": r.username, "ip": r.ip, "user_agent": r.user_agent}
        for r in rows
    ])

@app.route("/api/admin/audits")
@require_roles("admin")
def api_admin_audits():
    limit = max(1, min(int(request.args.get("limit", 100)), 1000))
    rows = AuditLog.query.order_by(AuditLog.ts.desc()).limit(limit).all()
    return jsonify([
        {"ts": r.ts.isoformat(), "action": r.action, "task_id": r.task_id,
         "role": r.role, "username": r.username,
         "details": json.loads(r.details or "{}")}
        for r in rows
    ])

@app.route("/api/admin/export")
@require_roles("admin")
def api_admin_export():
    kind = request.args.get("type")
    if kind not in {"access", "audit"}:
        return jsonify({"error": "type deve ser 'access' ou 'audit'"}), 400

    si = []
    def _csv(rows, header):
        si.append(",".join(header))
        for r in rows:
            si.append(",".join([str(x).replace(",", " ") if x is not None else "" for x in r]))
        return "\n".join(si)

    if kind == "access":
        rows = db.session.query(
            AccessLog.ts, AccessLog.action, AccessLog.role,
            AccessLog.username, AccessLog.ip, AccessLog.user_agent
        ).order_by(AccessLog.ts.desc()).all()
        data = _csv(rows, ["ts","action","role","username","ip","user_agent"])
        resp = make_response(data)
        resp.headers["Content-Type"] = "text/csv; charset=utf-8"
        resp.headers["Content-Disposition"] = "attachment; filename=access.csv"
        return resp

    rows = db.session.query(
        AuditLog.ts, AuditLog.action, AuditLog.task_id,
        AuditLog.role, AuditLog.username, AuditLog.details
    ).order_by(AuditLog.ts.desc()).all()
    # prettify details
    rows = [(r[0], r[1], r[2], r[3], r[4], json.loads(r[5] or "{}")) for r in rows]
    data = _csv(rows, ["ts","action","task_id","role","username","details"])
    resp = make_response(data)
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=audit.csv"
    return resp

# -----------------------------------------------------------------------------
# Inicialização e carga de dados mockados
# -----------------------------------------------------------------------------
def seed_if_empty():
    # Supervisores demo
    if Supervisor.query.count() == 0:
        db.session.add(Supervisor(username="super1", pass_hash=hash_password("super123")))
        db.session.add(Supervisor(username="super2", pass_hash=hash_password("super123")))
        db.session.commit()

    # 15 tarefas mockadas
    if Task.query.count() == 0:
        samples = [
            # title, sector, priority, status, responsavel, due_days, desc
            ("Organizar prateleiras setor C", "estoque", "alta", "em_andamento", "Larissa Silva",  7, "Reetiquetar caixas."),
            ("Treinamento de produto",       "vendas",  "baixa", "em_andamento", "Gustavo Freitas", 30, "Equipe regional."),
            ("Briefing campanha inverno",    "marketing","media","em_andamento", "Fernanda Melo",  10, "Definir público."),
            ("Backup mensal",                "ti",      "baixa", "concluida",    "Camila Dias",     0, "Armazenar no cold storage."),
            ("Parecer sobre LGPD",           "juridico","media","em_andamento", "Dr. Henrique",    14, "Coleta de dados no site."),
            ("Planilha de compras Q3",       "compras", "media","atrasada",     "Rafa Couto",     -2, "Cotações pendentes."),
            ("Fechamento de proposta X",     "vendas",  "alta", "em_andamento", "Patrícia Ramos",   5, "Enviar para diretoria."),
            ("Campanha de remarketing",      "marketing","baixa","em_andamento","Ana Tavares",     20, "Criar artes."),
            ("Inventário semanal",           "estoque", "media","concluida",    "João Pedro",       0, "Checar divergências."),
            ("Auditoria de contratos",       "juridico","alta", "em_andamento", "Marcela Soares",  12, "Revisar cláusulas."),
            ("Atualizar firewall",           "ti",      "alta", "em_andamento", "Bruno Lima",       3, "Janela de manutenção."),
            ("Negociação fornecedor Y",      "compras", "baixa","em_andamento", "Julia Nunes",     18, "Renovar acordo."),
            ("Script de integração ERP",     "ti",      "media","em_andamento", "Paulo Araújo",    9,  "Webhook inbound."),
            ("Pesquisa de satisfação",       "marketing","baixa","concluida",   "Equipe MKT",       0, "Enviar NPS."),
            ("Política de reembolso",        "juridico","media","em_andamento", "Equipe Legal",    21, "Novo documento."),
        ]
        now = date.today()
        for title, sec, prio, status, resp, dd, desc in samples:
            due = now + timedelta(days=dd)
            db.session.add(Task(
                title=title, sector_code=sec, priority=prio, status=status,
                responsavel=resp, due_date=due, description=desc,
                created_at=utcnow()
            ))
        db.session.commit()

with app.app_context():
    db.create_all()
    seed_if_empty()

# -----------------------------------------------------------------------------
# Run local
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # Para testes locais: flask run não é necessário
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
