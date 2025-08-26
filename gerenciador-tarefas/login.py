"""
login.py — Autenticação de ADMIN e SUPERVISOR (sem Flask)

Novidades:
- Função `authenticate_password(...)` que tenta admin primeiro e,
  se falhar, tenta supervisor. Retorna "admin", "supervisor" ou None.
- Restante continua igual: CRUD de supervisores e utilitários.
"""
from __future__ import annotations

import os
import re
import secrets
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

import hashlib

DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "tasks.db"))
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")

_PBKDF2_ALGO = "sha256"
_PBKDF2_ITERS = int(os.getenv("PBKDF2_ITERS", "200000"))
_PBKDF2_SALT_BYTES = 16

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")

@dataclass
class Supervisor:
    username: str
    created_at: str
    updated_at: Optional[str]
    is_active: int
    online: bool = False

    def to_public(self) -> Dict:
        d = asdict(self)
        d["is_active"] = bool(self.is_active)
        return d

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

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

def get_conn(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = db_path or DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

def init_users_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS supervisors (
            username TEXT PRIMARY KEY,
            pass_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    conn.commit()

def validate_username(username: str) -> bool:
    return bool(USERNAME_RE.fullmatch(username or ""))

def supervisor_exists(conn: sqlite3.Connection, username: str) -> bool:
    cur = conn.execute("SELECT 1 FROM supervisors WHERE username = ?", [username])
    return cur.fetchone() is not None

def create_supervisor(conn: sqlite3.Connection, username: str, password: str) -> None:
    if not validate_username(username):
        raise ValueError("Usuário inválido: use 3-32 chars [a-zA-Z0-9_.-]")
    if supervisor_exists(conn, username):
        raise ValueError("Usuário já existe")
    ph = hash_password(password)
    now = _now_iso()
    conn.execute(
        "INSERT INTO supervisors (username, pass_hash, created_at, is_active) VALUES (?,?,?,1)",
        [username, ph, now],
    )
    conn.commit()

def set_supervisor_password(conn: sqlite3.Connection, username: str, new_password: str) -> None:
    if not supervisor_exists(conn, username):
        raise ValueError("Usuário não encontrado")
    ph = hash_password(new_password)
    conn.execute(
        "UPDATE supervisors SET pass_hash = ?, updated_at = ? WHERE username = ?",
        [ph, _now_iso(), username],
    )
    conn.commit()

def delete_supervisor(conn: sqlite3.Connection, username: str) -> None:
    if not supervisor_exists(conn, username):
        raise ValueError("Usuário não encontrado")
    conn.execute("DELETE FROM supervisors WHERE username = ?", [username])
    conn.commit()

def list_supervisors(
    conn: sqlite3.Connection,
    active_usernames: Optional[Iterable[str]] = None,
) -> List[Supervisor]:
    rows = conn.execute(
        "SELECT username, created_at, updated_at, is_active FROM supervisors ORDER BY username ASC"
    ).fetchall()
    online_set = set(active_usernames or [])
    supvs = [
        Supervisor(
            username=r["username"],
            created_at=r["created_at"],
            updated_at=r["updated_at"],
            is_active=r["is_active"],
            online=(r["username"] in online_set),
        )
        for r in rows
    ]
    return supvs

def authenticate_admin(username: str, password: str) -> bool:
    return secrets.compare_digest(username or "", ADMIN_USER) and secrets.compare_digest(
        password or "", ADMIN_PASS
    )

def authenticate_supervisor(conn: sqlite3.Connection, username: str, password: str) -> bool:
    row = conn.execute(
        "SELECT pass_hash FROM supervisors WHERE username = ? AND is_active = 1",
        [username],
    ).fetchone()
    if not row:
        return False
    return verify_password(row["pass_hash"], password)

# ------ helper unificado OPCIONAL ------
def authenticate_password(conn: sqlite3.Connection, username: str, password: str) -> Optional[str]:
    """
    Tenta autenticar e retorna a role:
      - "admin"      se bater com variáveis ADMIN_USER/ADMIN_PASS
      - "supervisor" se bater na tabela supervisors
      - None         se não autenticar
    """
    if authenticate_admin(username, password):
        return "admin"
    if authenticate_supervisor(conn, username, password):
        return "supervisor"
    return None

def seed_supervisors(conn: sqlite3.Connection) -> None:
    cur = conn.execute("SELECT COUNT(*) FROM supervisors")
    if int(cur.fetchone()[0]) > 0:
        return
    create_supervisor(conn, "super1", "super123")
    create_supervisor(conn, "super2", "super123")

def usernames_online_from_sessions(sessions: Dict[str, Dict]) -> List[str]:
    try:
        return [
            s.get("username")
            for s in sessions.values()
            if s.get("role") == "supervisor" and s.get("username")
        ]
    except Exception:
        return []

if __name__ == "__main__":
    import sys
    conn = get_conn()
    init_users_schema(conn)
    if len(sys.argv) == 1:
        print("Uso:")
        print("  python login.py seed                         # cria super1/super2 (se vazio)")
        print("  python login.py add <usuario> <senha>")
        print("  python login.py passwd <usuario> <nova_senha>")
        print("  python login.py del <usuario>")
        sys.exit(0)

    cmd = sys.argv[1]
    try:
        if cmd == "seed":
            seed_supervisors(conn); print("OK: seed criado (super1/super2)")
        elif cmd == "add" and len(sys.argv) == 4:
            create_supervisor(conn, sys.argv[2], sys.argv[3]); print("OK: supervisor criado")
        elif cmd == "passwd" and len(sys.argv) == 4:
            set_supervisor_password(conn, sys.argv[2], sys.argv[3]); print("OK: senha atualizada")
        elif cmd == "del" and len(sys.argv) == 3:
            delete_supervisor(conn, sys.argv[2]); print("OK: supervisor removido")
        else:
            print("Comando inválido.")
    except Exception as e:
        print("Erro:", e)
