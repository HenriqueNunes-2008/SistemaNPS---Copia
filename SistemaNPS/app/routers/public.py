import re
import uuid
import hmac
import time
import base64
import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import quote_plus

from fastapi import APIRouter, Request, HTTPException, Response, Form, status
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from app.database import SessionLocal
from app.models import Perfil, Processo, ConfiguracaoSegura, ProjetoFoto
# Adicionamos o servico de upload (assumindo que existe em app.services.upload)
from app.services.upload import upload_pdf
from app.services.processo_repository import ProcessoRepository
import os
from urllib.parse import urlparse # Importar urlparse

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _extract_storage_path(public_url: str) -> str | None:
    """Extrai o caminho relativo do objeto dentro do bucket, limpando query strings como '?'."""
    if not public_url:
        return None
    parsed_url = urlparse(public_url)
    # parsed_url.path remove o que vem depois do '?' (query string)
    path_without_query = parsed_url.path 
    # Agora os arquivos ficam em /static/uploads/ no servidor
    if "/static/uploads/" in path_without_query:
        return path_without_query.split("/static/uploads/", 1)[1]
    return path_without_query


def _download_pdf(url: str) -> bytes:
    """Lê o arquivo do disco local (Magalu Cloud VM)."""
    try:
        with open(url.lstrip("/"), "rb") as f:
            return f.read()
    except Exception as e:
        if isinstance(e, HTTPException): raise e
        raise HTTPException(status_code=502, detail=f"Falha ao baixar arquivo do storage: {str(e)}")


def _extract_project_token(request: Request) -> str:
    # Tenta extrair token de varios parametros possiveis para robustez
    token = request.query_params.get("project_token")
    if not token:
        token = request.query_params.get("processo")
    if not token:
        token = request.query_params.get("id")
    if not token:
        token = request.cookies.get("project_token")
    return (token or "").strip()


def _token_is_active(token: str) -> bool:
    if not token:
        return False
    
    with SessionLocal() as session:
        row = session.query(Processo).filter(Processo.project_token == token).first()
    
    if not row:
        return False
    if row.project_token_ativo is False:
        return False

    expires = row.project_token_expira_em
    if not expires:
        return True
    try:
        exp_dt = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        return exp_dt >= datetime.now(timezone.utc)
    except Exception:
        return True


def _append_project_token(url: str, token: str) -> str:
    if not token:
        return url
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}project_token={token}"


def _get_admin_cookie_secret() -> str:
    return (
        os.getenv("ADMIN_ACTIVATION_COOKIE_SECRET")
        or os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or ""
    )


def _get_admin_activation_hash() -> str:
    """Busca o hash da senha administrativa no PostgreSQL."""
    with SessionLocal() as session:
        cfg = session.query(ConfiguracaoSegura).filter(ConfiguracaoSegura.chave == "admin_activation_hash").first()
        if cfg and cfg.valor_hash:
            return cfg.valor_hash.strip()
            
    return (os.getenv("ADMIN_ACTIVATION_HASH") or "").strip()


def _verify_admin_activation_password(password: str) -> bool:
    """
    Expected format for ADMIN_ACTIVATION_HASH:
    pbkdf2_sha256$<iterations>$<salt_base64>$<hash_base64>
    """
    encoded = _get_admin_activation_hash()
    if not encoded:
        return False

    parts = encoded.split("$")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        return False
    _, iter_str, salt_b64, hash_b64 = parts

    try:
        iterations = int(iter_str)
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        expected = base64.b64decode(hash_b64.encode("utf-8"))
    except Exception:
        return False

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=len(expected),
    )
    return hmac.compare_digest(derived, expected)


def _verify_admin_email_role(email: str) -> bool:
    """Verifica se o usuário é admin E se foi aprovado (status='ativo')."""
    with SessionLocal() as session:
        perfil = session.query(Perfil).filter(Perfil.email == email).first()
        if perfil:
            return perfil.role == "admin" and perfil.status == "ativo"
        return False

@router.post("/registrar")
def registrar_usuario(email: str = Form(...), password: str = Form(...)):
    """Cria conta com status 'pendente' para aprovação posterior."""
    with SessionLocal() as session:
        novo = Perfil(email=email, hashed_password=password, status="pendente")
        session.add(novo)
        session.commit()
    return JSONResponse({"message": "Cadastro realizado! Aguarde aprovação."})


def _encode_admin_activation_password(password: str, iterations: int = 390000) -> str:
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    hash_b64 = base64.b64encode(derived).decode("utf-8")
    return f"pbkdf2_sha256${iterations}${salt_b64}${hash_b64}"


def _build_admin_activation_cookie(max_age_seconds: int = 600) -> str:
    exp = str(int(time.time()) + max_age_seconds)
    secret = _get_admin_cookie_secret().encode("utf-8")
    signature = hmac.new(secret, exp.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{exp}.{signature}"


def _is_admin_activation_granted(request: Request) -> bool:
    raw = (request.cookies.get("admin_activation_ok") or "").strip()
    if "." not in raw:
        return False
    exp, signature = raw.split(".", 1)
    if not exp.isdigit():
        return False
    secret = _get_admin_cookie_secret()
    if not secret:
        return False
    expected = hmac.new(secret.encode("utf-8"), exp.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False
    return int(exp) >= int(time.time())


def _is_admin_mode_request(request: Request) -> bool:
    is_granted = _is_admin_activation_granted(request)
    # Considera modo admin apenas se tiver o cookie E (parâmetro admin=1 OU vindo do painel /admin)
    has_admin_param = request.query_params.get("admin") == "1" or request.query_params.get("return") == "/admin"
    return is_granted and has_admin_param


# REMOVIDO: /login alias - não mais necessário



@router.get("/admin-password", response_class=HTMLResponse)
def admin_password_page(request: Request):
    erro = request.query_params.get("erro")
    return templates.TemplateResponse(
        request=request,
        name="admin-password.html",
        context={"request": request, "erro": erro}
    )

@router.post("/admin-password")
def admin_password_post(email: str = Form(...), password: str = Form(...)):
    # 1. Validar se o e-mail tem perfil admin
    if not _verify_admin_email_role(email):
        erro = quote_plus("Acesso negado: e-mail não autorizado ou sem permissão administrativa.")
        return RedirectResponse(url=f"/admin-password?erro={erro}", status_code=303)

    # 2. Validar a senha administrativa (shared secret)
    if not _verify_admin_activation_password(password):
        erro = quote_plus("Senha inválida.")
        return RedirectResponse(url=f"/admin-password?erro={erro}", status_code=303)

    response = RedirectResponse(url="/admin", status_code=303)
    response.set_cookie(
        key="admin_activation_ok",
        value=_build_admin_activation_cookie(max_age_seconds=3600),  # 1h
        max_age=3600,
        httponly=True,
        samesite="lax",
    )
    return response


# REMOVIDO: login_submit - não mais necessário


@router.get("/index", response_class=HTMLResponse)
def index(request: Request):
    project_token = _extract_project_token(request)
    return templates.TemplateResponse(
        request=request,
        name="Index.html",
        context={"request": request, "project_token": project_token}
    )

# REMOVIDO: cadastro routes - não mais necessário


@router.get("/termo", response_class=HTMLResponse)
def termo(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="TermoAceite.html",
        context={
            "request": request,
            "project_token": _extract_project_token(request),
            "is_admin": _is_admin_mode_request(request)
        }
    )


@router.get("/ressalvas", response_class=HTMLResponse)
def ressalvas(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="Ressalvas.html",
        context={
            "request": request,
            "project_token": _extract_project_token(request),
            "is_admin": _is_admin_mode_request(request)
        }
    )


@router.get("/nps", response_class=HTMLResponse)
def nps(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="NPS2System.html",
        context={
            "request": request,
            "project_token": _extract_project_token(request),
            "is_admin": _is_admin_mode_request(request)
        }
    )


@router.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    if not _is_admin_activation_granted(request):
        return RedirectResponse(url="/admin-password", status_code=303)

    with SessionLocal() as session:
        # Busca todos os processos ordenados pelo mais recente
        processos_obj = session.query(Processo).order_by(Processo.criado_em.desc()).all()
        # Converte para dicionário para manter compatibilidade com o template Jinja
        processos = [p.__dict__ for p in processos_obj]

    for p in processos:
        nps_dados = p.get("nps_dados")
        if isinstance(nps_dados, str):
            try:
                nps_dados = json.loads(nps_dados)
            except Exception:
                nps_dados = {}
        if not isinstance(nps_dados, dict):
            nps_dados = {}
        p["nps_dados"] = nps_dados
        # Garante que o link de acesso seja sempre para o index com o token
        p["link_acesso"] = f"{str(request.base_url).rstrip('/')}/index?project_token={p.get('project_token')}"
        p["is_editable_by_admin"] = not bool(
            nps_dados.get("_edicao_bloqueada")
            or nps_dados.get("_lock_termo")
            or nps_dados.get("_lock_ressalvas")
            or nps_dados.get("_lock_nps")
        )
        
        # AJUSTE: Garante que p["codigo"] nunca seja None para os links de PDF no admin.html
        # Se o código humano estiver nulo, usamos o project_token ou o ID como fallback no link
        if not p.get("codigo"):
            p["codigo"] = p.get("project_token") or p.get("id")

        criado_em_raw = p.get("criado_em")
        created_text = str(criado_em_raw or "").strip()
        match_dt = re.match(r"^(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2})", created_text)
        if match_dt:
            yyyy, mm, dd, hh, mi = match_dt.groups()
            p["criado_em_fmt"] = f"{dd}/{mm}/{yyyy} {hh}:{mi}"
        else:
            match_d = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", created_text)
            if match_d:
                yyyy, mm, dd = match_d.groups()
                p["criado_em_fmt"] = f"{dd}/{mm}/{yyyy}"
            else:
                p["criado_em_fmt"] = created_text or "-"

    q = (request.query_params.get("q") or "").strip().lower()
    if q:
        processos = [
            p for p in processos
            if q in (p.get("project_token") or "").lower()
            or q in (p.get("projeto") or "").lower()
            or q in (p.get("nome_cliente") or "").lower()
            or q in (p.get("empresa") or "").lower()
        ]

    notas = [
        p.get("nps_nota") for p in processos
        if isinstance(p.get("nps_nota"), int)
    ]
    negativas = [n for n in notas if n <= 6]
    neutras = [n for n in notas if 7 <= n <= 8]
    positivas = [n for n in notas if n >= 9]

    def media(valores):
        return round(sum(valores) / len(valores), 2) if valores else None

    stats = {
        "total": len(processos),
        "com_termo": len([p for p in processos if p.get("termo_pdf")]),
        "com_ressalvas": len([p for p in processos if p.get("pdf_ressalvas")]),
        "com_nps": len([p for p in processos if p.get("nps_nota") is not None]),
        "media_negativas": media(negativas),
        "media_neutras": media(neutras),
        "media_positivas": media(positivas),
        "count_negativas": len(negativas),
        "count_neutras": len(neutras),
        "count_positivas": len(positivas)
    }

    response = templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "request": request,
            "processos": processos,
            "stats": stats,
            "q": q,
            "base_url": str(request.base_url).rstrip("/")
        }
    )
    # FORÇA O NAVEGADOR A NÃO FAZER CACHE DA PÁGINA ADMIN
    # Isso resolve o problema de reabrir a pagina e ver dados antigos (token ativo quando ja foi expirado)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@router.post("/admin/gerar-processo")
def admin_gerar_processo(request: Request):
    if not _is_admin_activation_granted(request):
        raise HTTPException(status_code=403, detail="Acesso restrito ao administrador")

    token = uuid.uuid4().hex[:12].upper()
    
    new_data = {
        "id": uuid.uuid4(),
        "status": "PENDENTE_TERMO",
        "status_entrega": "pendente_admin",
        "project_token": token,
        "project_token_ativo": True,
    }
    
    ProcessoRepository.insert(new_data)

    link = str(request.base_url).rstrip("/") + f"/index?project_token={token}"
    return JSONResponse({"success": True, "project_token": token, "link": link})


@router.post("/admin/update-project")
def admin_update_project(request: Request, project_token: str = Form(...), projeto: str = Form("")):
    if not _is_admin_activation_granted(request):
        raise HTTPException(status_code=403, detail="Acesso restrito")

    token = (project_token or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="Token invalido")

    with SessionLocal() as session:
        session.query(Processo).filter(Processo.project_token == token).update({"projeto": projeto})
        session.commit()
    
    return JSONResponse({"success": True})

@router.post("/admin/upload-foto-projeto")
def admin_upload_foto_projeto(
    request: Request, 
    projeto: str = Form(...), 
    observacao: str = Form(""),
    imagem: str = Form(...) # Base64 string
):
    if not _is_admin_activation_granted(request):
        raise HTTPException(status_code=403, detail="Acesso restrito")

    if not projeto or not imagem:
        raise HTTPException(status_code=400, detail="Projeto e Imagem são obrigatórios")

    # 1. Upload para o Storage (reutilizando a logica de upload existente)
    # Define uma pasta baseada no nome do projeto (limpeza basica)
    folder_name = "".join(x for x in projeto if x.isalnum() or x in " -_").strip()
    path = f"projetos_avulsos/{folder_name}"
    
    public_url = upload_pdf(imagem, path) # Retorna a URL publica

    if not public_url:
        raise HTTPException(status_code=500, detail="Erro ao fazer upload da imagem")

    # 2. Salvar no banco
    with SessionLocal() as session:
        nova_foto = ProjetoFoto(
            projeto=projeto,
            observacao=observacao,
            imagem_url=public_url
        )
        session.add(nova_foto)
        session.commit()
    
    return JSONResponse({"success": True})

@router.post("/admin/expirar-token")
def admin_expirar_token(
    request: Request,
    project_token: str = Form(...),
):
    if not _is_admin_activation_granted(request):
        raise HTTPException(status_code=403, detail="Acesso restrito ao administrador")


    token = (project_token or "").strip().upper()
    if not token:
        raise HTTPException(status_code=400, detail="Project token obrigatorio")

    now = datetime.now(timezone.utc)
    with SessionLocal() as session:
        updated = session.query(Processo).filter(Processo.project_token == token).update({
            "project_token_expira_em": now,
            "project_token_ativo": False,
        })
        session.commit()

    if not updated:
        raise HTTPException(status_code=404, detail="Processo nao encontrado para o token informado")

    return JSONResponse(
        {
            "success": True,
            "project_token": token,
            "project_token_expira_em": now.isoformat(),
        }
    )


@router.post("/admin/alterar-senha-acesso")
def alterar_senha_acesso(
    request: Request,
    senha_atual: str = Form(...),
    nova_senha: str = Form(...),
    confirmar_senha: str = Form(...)
):
    """Altera a senha global de ativação administrativa em configuracoes_seguras."""
    if not _is_admin_activation_granted(request):
        raise HTTPException(status_code=403, detail="Sessão administrativa expirada ou inválida.")

    if nova_senha != confirmar_senha:
        raise HTTPException(status_code=400, detail="A confirmação de senha não confere.")

    # Valida senha atual antes de permitir a troca
    if not _verify_admin_activation_password(senha_atual):
        raise HTTPException(status_code=400, detail="Senha atual incorreta.")

    novo_hash = _encode_admin_activation_password(nova_senha)
    
    with SessionLocal() as session:
        session.query(ConfiguracaoSegura).filter(ConfiguracaoSegura.chave == "admin_activation_hash").update({
            "valor_hash": novo_hash,
            "atualizado_em": datetime.now(timezone.utc),
            "atualizado_por": "Painel Admin"
        })
        session.commit()

    return {"success": True}


# REMOVIDO: alterar senha admin - não mais necessário


@router.post("/admin/toggle-lock")
def admin_toggle_edit_lock(
    request: Request,
    project_token: str = Form(...),
):
    if not _is_admin_activation_granted(request):
        raise HTTPException(status_code=403, detail="Acesso restrito ao administrador")


    token = (project_token or "").strip().upper()
    if not token:
        raise HTTPException(status_code=400, detail="Project token obrigatorio")

    with SessionLocal() as session:
        proc = session.query(Processo).filter(Processo.project_token == token).first()
    
    if not proc:
        raise HTTPException(status_code=404, detail="Processo nao encontrado para o token informado")

    nps_dados = proc.nps_dados
    if isinstance(nps_dados, str):
        try:
            nps_dados = json.loads(nps_dados)
        except Exception:
            nps_dados = {}
    if not isinstance(nps_dados, dict):
        nps_dados = {}

    # Logica simplificada: se Termo ou Ressalvas estao travados, consideramos bloqueado (estado de envio pro cliente)
    is_locked_for_client = bool(nps_dados.get("_lock_termo") or nps_dados.get("_lock_ressalvas"))
    now = datetime.now(timezone.utc)
    actor = "Administrador"

    if is_locked_for_client:
        nps_dados["_lock_termo"] = False
        nps_dados["_lock_ressalvas"] = False
        nps_dados["_lock_nps"] = False
        nps_dados["_edicao_liberada_em"] = now.isoformat()
        nps_dados["_edicao_liberada_por"] = actor
        is_editable_by_admin = True
    else:
        # Bloqueia Termo/Ressalvas (para admin nao mexer sem querer) e Libera NPS (para cliente preencher)
        nps_dados["_lock_termo"] = True
        nps_dados["_lock_ressalvas"] = True
        nps_dados["_lock_nps"] = False
        nps_dados["_edicao_fechada_em"] = now.isoformat()
        nps_dados["_edicao_fechada_por"] = actor
        is_editable_by_admin = False

    with SessionLocal() as session:
        session.query(Processo).filter(Processo.id == proc.id).update({"nps_dados": nps_dados})
        session.commit()

    return JSONResponse({"success": True, "project_token": token, "is_editable_by_admin": is_editable_by_admin})

@router.get("/api/processos/{identificador}")
def api_obter_processo(identificador: str):
    try:
        proc = ProcessoRepository.get_by_identifier(
            identificador,
            "id,codigo,project_token,nome_cliente,cpf,status,status_entrega,nps_nota,nps_dados,project_token_ativo,project_token_expira_em"
        )
        if not proc:
            raise HTTPException(status_code=404, detail="Processo não encontrado")
        return proc
    except Exception:
        raise HTTPException(status_code=404, detail="Processo não encontrado")

@router.get("/nps-motor", response_class=HTMLResponse)
def nps_motor(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="NPSMotor.html",
        context={"request": request, "project_token": _extract_project_token(request)}
    )


@router.get("/pdf/termo/{codigo}")
def pdf_termo(codigo: str):
    proc = ProcessoRepository.get_by_identifier(codigo, "termo_pdf")
    if not proc or not proc.get("termo_pdf"):
        raise HTTPException(status_code=404, detail="PDF do termo não encontrado")

    pdf_bytes = _download_pdf(proc["termo_pdf"])
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": "inline; filename=termo.pdf",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )


@router.get("/pdf/ressalvas/{codigo}")
def pdf_ressalvas(codigo: str):
    proc = ProcessoRepository.get_by_identifier(codigo, "pdf_ressalvas")
    if not proc or not proc.get("pdf_ressalvas"):
        raise HTTPException(status_code=404, detail="PDF de ressalvas não encontrado")

    pdf_bytes = _download_pdf(proc["pdf_ressalvas"])
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": "inline; filename=ressalvas.pdf",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )


@router.get("/pdf/final/{codigo}")
def pdf_final(codigo: str):
    proc = ProcessoRepository.get_by_identifier(codigo, "pdf_final")
    if not proc or not proc.get("pdf_final"):
        raise HTTPException(status_code=404, detail="PDF final não encontrado")

    pdf_bytes = _download_pdf(proc["pdf_final"])
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": "inline; filename=entrega_final.pdf",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )

@router.get("/.well-known/appspecific/com.chrome.devtools.json")
def chrome_devtools():
    return {}

@router.get("/logout")
def logout():
    response = RedirectResponse(
        url="/admin-password",
        status_code=status.HTTP_303_SEE_OTHER
    )
    # Remove o cookie de autenticação para encerrar a sessão
    response.delete_cookie("nps_user")
    response.delete_cookie("nps_role")
    response.delete_cookie("project_token")
    response.delete_cookie("nps_tipo_acesso")
    response.delete_cookie("admin_activation_ok")
    return response
