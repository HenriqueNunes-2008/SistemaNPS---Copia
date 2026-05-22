from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# DATABASE_URL deve ser configurada no ambiente da Magalu Cloud
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:senha@ip-da-vm:5432/nps_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Provedor de sessão para as rotas do FastAPI."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()