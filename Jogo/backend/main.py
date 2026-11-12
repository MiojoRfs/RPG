import os
import re
import time
import hmac
import hashlib
import secrets
from datetime import datetime, timezone
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


Base.metadata.create_all(bind=engine)


def migrate():
    """Adiciona as colunas novas em bancos que já existiam (create_all não faz isso)."""
    cols = {c["name"] for c in inspect(engine).get_columns("players")}
    with engine.begin() as conn:
        for name in ("pw_hash", "token"):
            if name not in cols:
                conn.execute(text(f"ALTER TABLE players ADD COLUMN {name} VARCHAR"))


migrate()

app = FastAPI()

# Atualize APP_VERSION junto com o VERSION do index.html a cada atualização
APP_VERSION = "1.2.0"
STARTED_AT = datetime.now(timezone.utc).isoformat()

# Chave para redefinir senhas (configure ADMIN_KEY no Render; sem ela a rota fica desligada)
ADMIN_KEY = os.getenv("ADMIN_KEY")

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
    return player


def issue_token(player: PlayerModel) -> str:
    player.token = secrets.token_urlsafe(32)  # novo login derruba a sessão anterior
    return player.token


# Rota 0: criar conta
@app.post("/api/register")
def register(c: Credentials, db: Session = Depends(get_db)):
    u = clean_credentials(c)
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
        player.pw_hash = hash_pw(c.password)
    elif not check_pw(c.password, player.pw_hash):
        FAILS[u] = (FAILS.get(u, (0, 0.0))[0] + 1, time.time())
        raise HTTPException(401, "Usuário ou senha incorretos.")
    FAILS.pop(u, None)
    token = issue_token(player)
    db.commit()
    return {"token": token}


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

    db.commit()
    return {"status": "sucesso", "message": "Dados salvos no banco de dados!"}


# Rota 2: Carregar Progresso do Banco
@app.get("/api/load/{username}")
def load_game(username: str, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    player = auth_player(username, authorization, db)
    if not player.data:
        return {"status": "novo", "player_data": None}
    return {"status": "encontrado", "player_data": player.data}


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
        if p.data
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
    player = db.query(PlayerModel).filter(PlayerModel.username == b.username.strip().lower()).first()
    if not player:
        raise HTTPException(404, "Jogador não encontrado.")
    player.pw_hash = hash_pw(b.new_password)
    player.token = None  # derruba a sessão aberta
    db.commit()
    return {"status": "ok", "message": f"Senha de {player.username} redefinida."}
