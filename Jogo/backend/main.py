import os
import re
import time
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, JSON, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# Puxa a URL do banco das variáveis de ambiente (se não achar, usa o SQLite local)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./eldoria.db")

# Força o uso do psycopg2 independente de como a URL veio do Supabase
if DATABASE_URL.startswith("postgres"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

# Remove o connect_args do SQLite se estiver rodando no Postgres
if "sqlite" in DATABASE_URL:
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class PlayerModel(Base):
    __tablename__ = "players"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    level = Column(Integer, default=1)
    cp = Column(Integer, default=0)
    data = Column(JSON)
    pw_hash = Column(String, nullable=True)  # "salt$hash" (PBKDF2)
    token = Column(String, nullable=True)    # token da sessão ativa
    banned_until = Column(Integer, nullable=True)  # epoch em segundos (2147483647 = permanente)
    ban_reason = Column(String, nullable=True)
    pending = Column(JSON, nullable=True)    # ações do administrador esperando o jogador sincronizar


Base.metadata.create_all(bind=engine)


def migrate():
    """Adiciona as colunas novas em bancos que já existiam (create_all não faz isso)."""
    cols = {c["name"] for c in inspect(engine).get_columns("players")}
    new_cols = {"pw_hash": "VARCHAR", "token": "VARCHAR", "banned_until": "INTEGER",
                "ban_reason": "VARCHAR", "pending": "JSON"}
    with engine.begin() as conn:
        for name, typ in new_cols.items():
            if name not in cols:
                conn.execute(text(f"ALTER TABLE players ADD COLUMN {name} {typ}"))


migrate()

app = FastAPI()

# Atualize APP_VERSION junto com o VERSION do index.html a cada atualização
APP_VERSION = "1.3.0"
STARTED_AT = datetime.now(timezone.utc).isoformat()

# Chave para redefinir senhas (configure ADMIN_KEY no Render; sem ela a rota fica desligada)
ADMIN_KEY = os.getenv("ADMIN_KEY")

# Contas de administrador (nomes separados por vírgula). Esses nomes são reservados.
ADMINS = {n.strip().lower() for n in os.getenv("ADMIN_USERS", "adm").split(",") if n.strip()}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type", "X-Admin-Key"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------- Senhas e sessão ----------
USER_RE = re.compile(r"^[a-z0-9_]{3,16}$")
FAILS = {}  # username -> (tentativas, instante da última falha)


def hash_pw(pw: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()
    return f"{salt}${h}"


def check_pw(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()
    except ValueError:
        return False
    return hmac.compare_digest(calc.encode(), h.encode())


def same(a: Optional[str], b: Optional[str]) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(a.encode(), b.encode())


class Credentials(BaseModel):
    username: str
    password: str


class ResetBody(BaseModel):
    username: str
    new_password: str


def clean_credentials(c: Credentials) -> str:
    u = c.username.strip().lower()
    if not USER_RE.match(u):
        raise HTTPException(400, "Use de 3 a 16 caracteres: letras, números ou _ no usuário.")
    if not (4 <= len(c.password) <= 128):
        raise HTTPException(400, "A senha precisa ter de 4 a 128 caracteres.")
    return u


def throttle(u: str):
    n, t = FAILS.get(u, (0, 0.0))
    if n >= 8:
        if time.time() - t < 60:
            raise HTTPException(429, "Muitas tentativas. Aguarde 1 minuto.")
        FAILS.pop(u, None)


def auth_player(username: str, authorization: Optional[str], db: Session) -> PlayerModel:
    token = (authorization or "").replace("Bearer ", "", 1).strip()
    player = db.query(PlayerModel).filter(PlayerModel.username == username.strip().lower()).first()
    if not player or not same(player.token, token):
        raise HTTPException(401, "Sessão inválida. Entre novamente.")
    if is_banned(player):
        raise HTTPException(403, ban_msg(player))
    return player


def issue_token(player: PlayerModel) -> str:
    player.token = secrets.token_urlsafe(32)  # novo login derruba a sessão anterior
    return player.token


# ---------- Banimento e ações do administrador ----------
PERM_BAN = 2147483647
BRT = timezone(timedelta(hours=-3))


def is_banned(p: PlayerModel) -> bool:
    return bool(p.banned_until) and p.banned_until > time.time()


def ban_msg(p: PlayerModel) -> str:
    motivo = f" Motivo: {p.ban_reason}." if p.ban_reason else ""
    if p.banned_until >= PERM_BAN:
        return "Conta banida permanentemente." + motivo
    ate = datetime.fromtimestamp(p.banned_until, BRT).strftime("%d/%m/%Y %H:%M")
    return f"Conta banida até {ate} (horário de Brasília)." + motivo


def apply_pending(player: PlayerModel) -> bool:
    """Aplica no save as ações que o administrador deixou na fila. True se mudou algo."""
    acts = player.pending or []
    if not acts or not isinstance(player.data, dict):
        return False
    d = dict(player.data)
    inv = dict(d.get("inv") or {})
    for a in acts:
        t = a.get("t")
        if t == "item":
            inv[a["id"]] = max(0, int(inv.get(a["id"], 0)) + int(a["q"]))
        elif t == "gold":
            d["gold"] = max(0, float(d.get("gold", 0)) + int(a["q"]))
        elif t == "level":
            novo, antigo = int(a["v"]), int(d.get("level", 1))
            d["level"], d["xp"] = novo, 0
            if novo > antigo:
                d["pts"] = int(d.get("pts", 0)) + 3 * (novo - antigo)
    d["inv"] = inv
    player.data = d
    player.level = int(d.get("level", 1))
    player.pending = []
    return True


# Rota 0: criar conta
@app.post("/api/register")
def register(c: Credentials, db: Session = Depends(get_db)):
    u = clean_credentials(c)
    if u in ADMINS:
        raise HTTPException(403, "Esse nome é reservado.")
    player = db.query(PlayerModel).filter(PlayerModel.username == u).first()
    if player and player.pw_hash:
        raise HTTPException(409, "Esse usuário já existe. Escolha outro nome.")
    if not player:  # se existir sem senha, é uma conta antiga: quem registrar primeiro assume
        player = PlayerModel(username=u)
        db.add(player)
    player.pw_hash = hash_pw(c.password)
    token = issue_token(player)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Esse usuário já existe. Escolha outro nome.")
    return {"token": token}


# Rota 0b: entrar
@app.post("/api/login")
def login(c: Credentials, db: Session = Depends(get_db)):
    u = clean_credentials(c)
    throttle(u)
    player = db.query(PlayerModel).filter(PlayerModel.username == u).first()
    if not player:
        FAILS[u] = (FAILS.get(u, (0, 0.0))[0] + 1, time.time())
        raise HTTPException(401, "Usuário ou senha incorretos.")
    if not player.pw_hash:  # conta antiga, sem senha: a primeira senha informada passa a valer
        if u in ADMINS:
            raise HTTPException(403, "Conta de administrador ainda não foi configurada.")
        player.pw_hash = hash_pw(c.password)
    elif not check_pw(c.password, player.pw_hash):
        FAILS[u] = (FAILS.get(u, (0, 0.0))[0] + 1, time.time())
        raise HTTPException(401, "Usuário ou senha incorretos.")
    FAILS.pop(u, None)
    if is_banned(player):
        raise HTTPException(403, ban_msg(player))
    token = issue_token(player)
    db.commit()
    return {"token": token, "admin": u in ADMINS}


# Rota 1: Salvar ou Atualizar Progresso
@app.post("/api/save")
def save_game(payload: dict, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    username = str(payload.get("username") or "").strip().lower()
    player_data = payload.get("player_data")

    if not username or not isinstance(player_data, dict) or not player_data:
        raise HTTPException(status_code=400, detail="Dados inválidos")

    player = auth_player(username, authorization, db)

    # Não deixa um save antigo sobrescrever um mais novo
    if player.data and player.data.get("last", 0) > player_data.get("last", 0):
        return {"status": "ignorado", "message": "Save mais antigo que o do servidor"}

    player.level = int(player_data.get("level", 1))
    player.cp = int(player_data.get("cp", 0))
    player.data = player_data
    applied = apply_pending(player)  # ações do administrador entram aqui

    db.commit()
    return {"status": "sucesso", "updated": player.data if applied else None}


# Rota 2: Carregar Progresso do Banco
@app.get("/api/load/{username}")
def load_game(username: str, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    player = auth_player(username, authorization, db)
    if apply_pending(player):
        db.commit()
    admin = player.username in ADMINS
    if not player.data:
        return {"status": "novo", "player_data": None, "admin": admin}
    return {"status": "encontrado", "player_data": player.data, "admin": admin}


# Rota 3: Ranking Global Real (público)
@app.get("/api/ranking")
def get_ranking(db: Session = Depends(get_db)):
    players = db.query(PlayerModel).order_by(PlayerModel.cp.desc()).limit(50).all()
    return [
        {
            "n": p.username,
            "u": p.username,
            "l": p.level,
            "cp": p.cp,
            "cls": p.data.get("cls", "guerreiro"),
        }
        for p in players
        if p.data and p.username not in ADMINS and not is_banned(p)
    ][:20]


# Rota 4: Versão e status do servidor (usada pelo painel de novidades do jogo)
@app.get("/api/version")
def version():
    return {
        "version": APP_VERSION,
        "commit": (os.getenv("RENDER_GIT_COMMIT") or "local")[:7],
        "started_at": STARTED_AT,
        "db": "sqlite" if "sqlite" in DATABASE_URL else "postgres",
    }


# Rota 5 (administrador): redefinir a senha de um jogador
@app.post("/api/admin/reset-password")
def admin_reset(b: ResetBody, x_admin_key: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not ADMIN_KEY or not same(x_admin_key, ADMIN_KEY):
        raise HTTPException(403, "Não autorizado.")
    if not (4 <= len(b.new_password) <= 128):
        raise HTTPException(400, "A senha precisa ter de 4 a 128 caracteres.")
    u = b.username.strip().lower()
    player = db.query(PlayerModel).filter(PlayerModel.username == u).first()
    if not player:
        if u not in ADMINS:
            raise HTTPException(404, "Jogador não encontrado.")
        player = PlayerModel(username=u)  # é assim que a conta de administrador é criada
        db.add(player)
    player.pw_hash = hash_pw(b.new_password)
    player.token = None  # derruba a sessão aberta
    db.commit()
    return {"status": "ok", "message": f"Senha de {player.username} redefinida."}


# ---------- Painel do administrador (só contas em ADMIN_USERS) ----------
def require_admin(authorization: Optional[str], db: Session) -> PlayerModel:
    token = (authorization or "").replace("Bearer ", "", 1).strip()
    p = db.query(PlayerModel).filter(PlayerModel.token == token).first() if token else None
    if not p or p.username not in ADMINS or not same(p.token, token):
        raise HTTPException(403, "Acesso restrito ao administrador.")
    return p


def get_target(db: Session, username: str) -> PlayerModel:
    t = db.query(PlayerModel).filter(PlayerModel.username == username.strip().lower()).first()
    if not t:
        raise HTTPException(404, "Jogador não encontrado.")
    return t


class AdminAction(BaseModel):
    username: str
    t: str                      # "item", "gold" ou "level"
    id: Optional[str] = None    # item
    q: Optional[int] = None     # quantidade (item/ouro); negativo remove
    v: Optional[int] = None     # nível


class BanBody(BaseModel):
    username: str
    reason: str = ""
    hours: int = 0              # 0 = permanente


class UserBody(BaseModel):
    username: str


@app.get("/api/admin/players")
def admin_players(q: str = "", authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    require_admin(authorization, db)
    query = db.query(PlayerModel)
    if q.strip():
        query = query.filter(PlayerModel.username.contains(q.strip().lower()))
    rows = query.order_by(PlayerModel.username).limit(200).all()
    return [{"u": p.username, "l": p.level or 1, "cp": p.cp or 0,
             "banned": is_banned(p), "admin": p.username in ADMINS} for p in rows]


@app.get("/api/admin/player/{username}")
def admin_player(username: str, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    require_admin(authorization, db)
    t = get_target(db, username)
    return {"username": t.username, "banned": is_banned(t),
            "ban_msg": ban_msg(t) if is_banned(t) else "",
            "pending": len(t.pending or []), "data": t.data}


@app.post("/api/admin/action")
def admin_action(b: AdminAction, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    require_admin(authorization, db)
    t = get_target(db, b.username)
    if b.t == "item":
        if not b.id or not re.match(r"^[a-z0-9_]{1,30}$", b.id) or not b.q or abs(b.q) > 1_000_000:
            raise HTTPException(400, "Item ou quantidade inválidos.")
        act = {"t": "item", "id": b.id, "q": b.q}
    elif b.t == "gold":
        if not b.q or abs(b.q) > 1_000_000_000:
            raise HTTPException(400, "Quantidade inválida.")
        act = {"t": "gold", "q": b.q}
    elif b.t == "level":
        if b.v is None or not (1 <= b.v <= 1000):
            raise HTTPException(400, "Nível deve ficar entre 1 e 1000.")
        act = {"t": "level", "v": b.v}
    else:
        raise HTTPException(400, "Ação desconhecida.")
    t.pending = list(t.pending or []) + [act]
    db.commit()
    return {"status": "ok", "pending": len(t.pending)}


@app.post("/api/admin/ban")
def admin_ban(b: BanBody, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    require_admin(authorization, db)
    t = get_target(db, b.username)
    if t.username in ADMINS:
        raise HTTPException(400, "Não é possível banir um administrador.")
    hours = max(0, min(b.hours, 24 * 365 * 5))
    t.banned_until = PERM_BAN if hours == 0 else int(time.time() + hours * 3600)
    t.ban_reason = b.reason.strip()[:200]
    t.token = None  # derruba a sessão aberta
    db.commit()
    return {"status": "ok"}


@app.post("/api/admin/unban")
def admin_unban(b: UserBody, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    require_admin(authorization, db)
    t = get_target(db, b.username)
    t.banned_until = None
    t.ban_reason = None
    db.commit()
    return {"status": "ok"}


@app.post("/api/admin/set-password")
def admin_set_password(b: ResetBody, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    require_admin(authorization, db)
    if not (4 <= len(b.new_password) <= 128):
        raise HTTPException(400, "A senha precisa ter de 4 a 128 caracteres.")
    t = get_target(db, b.username)
    t.pw_hash = hash_pw(b.new_password)
    t.token = None
    db.commit()
    return {"status": "ok"}


@app.post("/api/admin/delete")
def admin_delete(b: UserBody, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    require_admin(authorization, db)
    t = get_target(db, b.username)
    if t.username in ADMINS:
        raise HTTPException(400, "Não é possível excluir um administrador.")
    db.delete(t)
    db.commit()
    return {"status": "ok"}
