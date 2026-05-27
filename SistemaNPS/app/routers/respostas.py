from fastapi import APIRouter
from app.schemas import RespostaCreate
from app.services.resposta_repository import RespostaRepository

router = APIRouter(prefix="/api")

@router.post("/respostas")
def salvar_resposta(resposta: RespostaCreate):
    RespostaRepository.insert({
        "cliente_id": resposta.cliente_id,
        "pagina": resposta.pagina,
        "dados": resposta.dados
    })
    return {"status": "ok"}
