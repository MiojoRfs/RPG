import os
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, JSON
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# Puxa a URL do banco das variáveis de ambiente (se não achar, usa o SQLite local)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./eldoria.db")

# Ajuste necessário para o SQLAlchemy entender algumas URLs do Postgres
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

# (O resto do seu código das tabelas e rotas continua exatamente igual)

# Tabela do Banco de Dados
class PlayerModel(Base):
    __tablename__ = "players"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    level = Column(Integer, default=1)
    cp = Column(Integer, default=0)
    data = Column(JSON)

Base.metadata.create_all(bind=engine)

app = FastAPI()

# Atualize APP_VERSION junto com o VERSION do index.html a cada atualização
APP_VERSION = "1.1.0"
STARTED_AT = datetime.now(timezone.utc).isoformat()

# Permite que seu Front-end (Netlify / Live Server) converse com essa API sem bloqueios de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Rota 1: Salvar ou Atualizar Progresso
@app.post("/api/save")
def save_game(payload: dict, db: Session = Depends(get_db)):
    username = payload.get("username")
    player_data = payload.get("player_data")
    
    if not username or not player_data:
        raise HTTPException(status_code=400, detail="Dados inválidos")
    
    player = db.query(PlayerModel).filter(PlayerModel.username == username).first()
    
    if not player:
        player = PlayerModel(username=username)
        db.add(player)
    
    # Não deixa um save antigo sobrescrever um mais novo
    if player.data and player.data.get("last", 0) > player_data.get("last", 0):
        return {"status": "ignorado", "message": "Save mais antigo que o do servidor"}

    player.level = player_data.get("level", 1)
    player.cp = player_data.get("cp", 0)
    player.data = player_data
    
    db.commit()
    return {"status": "sucesso", "message": "Dados salvos no banco de dados!"}

# Rota 2: Carregar Progresso do Banco
@app.get("/api/load/{username}")
def load_game(username: str, db: Session = Depends(get_db)):
    player = db.query(PlayerModel).filter(PlayerModel.username == username).first()
    if not player:
        return {"status": "novo", "player_data": None}
    return {"status": "encontrado", "player_data": player.data}

# Rota 3: Ranking Global Real (Lê todos os jogares do banco)
@app.get("/api/ranking")
def get_ranking(db: Session = Depends(get_db)):
    players = db.query(PlayerModel).order_by(PlayerModel.cp.desc()).limit(20).all()
    return [
        {
            "n": p.username,
            "u": p.username,
            "l": p.level,
            "cp": p.cp,
            "cls": p.data.get("cls", "guerreiro") if p.data else "guerreiro"
        }
        for p in players
    ]


# Rota 4: Versão e status do servidor (usada pelo painel de novidades do jogo)
@app.get("/api/version")
def version():
    return {
        "version": APP_VERSION,
        "commit": (os.getenv("RENDER_GIT_COMMIT") or "local")[:7],
        "started_at": STARTED_AT,
        "db": "sqlite" if "sqlite" in DATABASE_URL else "postgres",
    }
