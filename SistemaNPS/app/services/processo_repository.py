import uuid
from typing import Optional, Dict, Any, List
from app.database import SessionLocal
from app.models import Processo, RessalvaItem
from sqlalchemy import or_, String

class ProcessoRepository:
    """Operações de banco migradas de Supabase para SQLAlchemy/PostgreSQL."""
    
    @staticmethod
    def get_by_identifier(identifier: str, select: str = "*") -> Optional[Dict[str, Any]]:
        if not identifier or str(identifier).lower() == "none":
            return None
            
        with SessionLocal() as session:
            query = session.query(Processo)
            # Busca flexível por UUID, token ou código humano
            proc = query.filter(or_(
                Processo.id.cast(String) == identifier,
                Processo.project_token == identifier,
                Processo.codigo == identifier
            )).first()
            return proc.__dict__ if proc else None

    @staticmethod
    def insert(data: Dict[str, Any]) -> Dict[str, Any]:
        with SessionLocal() as session:
            new_proc = Processo(**data)
            session.add(new_proc)
            session.commit()
            session.refresh(new_proc)
            return new_proc.__dict__

    @staticmethod
    def update(processo_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        with SessionLocal() as session:
            session.query(Processo).filter(Processo.id == processo_id).update(data)
            session.commit()
            updated = session.query(Processo).filter(Processo.id == processo_id).first()
            return updated.__dict__

    @staticmethod
    def insert_ressalvas_itens(itens: List[Dict[str, Any]]):
        with SessionLocal() as session:
            objs = [RessalvaItem(**item) for item in itens]
            session.bulk_save_objects(objs)
            session.commit()

    @staticmethod
    def delete_ressalvas_itens(processo_uuid: str):
        with SessionLocal() as session:
            session.query(RessalvaItem).filter(RessalvaItem.processo_id == processo_uuid).delete()
            session.commit()

    @staticmethod
    def get_ressalvas_itens(processo_uuid: str) -> List[Dict[str, Any]]:
        """Busca itens de ressalva para um processo."""
        with SessionLocal() as session:
            itens = session.query(RessalvaItem).filter(RessalvaItem.processo_id == processo_uuid).all()
            return [i.__dict__ for i in itens]
