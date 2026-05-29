from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Date
from sqlalchemy.dialects.postgresql import UUID, JSONB
from .database import Base
import uuid
from datetime import datetime, timezone

class Perfil(Base):
    """Tabela de usuários com controle de aprovação administrativa."""
    __tablename__ = "perfis"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    nome = Column(String)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user")
    status = Column(String, default="pendente") # pendente, ativo, bloqueado
    criado_em = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Processo(Base):
    """Tabela principal dos processos NPS, migrada do Supabase."""
    __tablename__ = "processos"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_token = Column(String, unique=True, index=True)
    codigo = Column(String, unique=True, index=True)
    projeto = Column(String)
    nome_cliente = Column(String)
    empresa = Column(String)
    cpf = Column(String)
    status = Column(String)
    status_entrega = Column(String)
    
    # Campos JSONB para manter a flexibilidade do esquema anterior
    termo_dados = Column(JSONB)
    ressalvas_dados = Column(JSONB)
    nps_dados = Column(JSONB)
    imagens_termo = Column(JSONB)
    
    termo_pdf = Column(String)
    pdf_ressalvas = Column(String)
    pdf_final = Column(String)
    nps_nota = Column(Integer)
    
    finalizado_em = Column(Date)
    project_token_ativo = Column(Boolean, default=True)
    project_token_expira_em = Column(DateTime)
    criado_em = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    atualizado_em = Column(DateTime, onupdate=lambda: datetime.now(timezone.utc))

class RessalvaItem(Base):
    """Itens detalhados de ressalvas vinculados a um processo."""
    __tablename__ = "ressalvas_itens"
    
    id = Column(Integer, primary_key=True, index=True)
    processo_id = Column(UUID(as_uuid=True), ForeignKey("processos.id"))
    item = Column(String)
    descricao = Column(String)
    prazo = Column(Date)
    responsavel = Column(String)
    observacao = Column(String)
    aprovacao = Column(Boolean, default=False)
    imagem_hash = Column(String)
    criado_em = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class ConfiguracaoSegura(Base):
    """Configurações globais do sistema (ex: hash da senha admin)."""
    __tablename__ = "configuracoes_seguras"
    chave = Column(String, primary_key=True)
    valor_hash = Column(String)
    atualizado_em = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    atualizado_por = Column(String)

class ProjetoFoto(Base):
    """Registro de fotos enviadas via painel administrativo."""
    __tablename__ = "projetos_fotos"
    id = Column(Integer, primary_key=True, index=True)
    projeto = Column(String)
    observacao = Column(String)
    imagem_url = Column(String)

class Resposta(Base):
    """Tabela para armazenar respostas de formulários (anteriormente no Supabase)."""
    __tablename__ = "respostas"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cliente_id = Column(String, index=True, nullable=False)
    pagina = Column(String, nullable=False)
    dados = Column(JSONB)
    criado_em = Column(DateTime, default=lambda: datetime.now(timezone.utc))