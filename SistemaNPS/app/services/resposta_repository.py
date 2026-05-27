from typing import Dict, Any
from app.database import SessionLocal
from app.models import Resposta
import uuid
from datetime import datetime, timezone

class RespostaRepository:
    """Repositório para operações de Respostas no PostgreSQL."""

    @staticmethod
    def insert(data: Dict[str, Any]) -> Dict[str, Any]:
        with SessionLocal() as session:
            # Garante que o ID e a data de criação sejam definidos se não vierem no payload
            if "id" not in data: data["id"] = uuid.uuid4()
            if "criado_em" not in data: data["criado_em"] = datetime.now(timezone.utc)
            
            new_resposta = Resposta(**data)
            session.add(new_resposta)
            session.commit()
            session.refresh(new_resposta)
            return new_resposta.__dict__