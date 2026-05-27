import os
import hashlib
import base64
from app.database import SessionLocal
from app.models import Perfil, ConfiguracaoSegura
from datetime import datetime, timezone

def encode_password(password: str, iterations: int = 390000) -> str:
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=32
    )
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    hash_b64 = base64.b64encode(derived).decode("utf-8")
    return f"pbkdf2_sha256${iterations}${salt_b64}${hash_b64}"

def setup_first_admin():
    email = input("Digite o e-mail do administrador: ").strip().lower()
    password = input("Digite a senha do administrador: ").strip()
    
    hashed = encode_password(password)
    
    with SessionLocal() as db:
        # 1. Cria ou atualiza o perfil como Admin Ativo
        user = db.query(Perfil).filter(Perfil.email == email).first()
        if not user:
            user = Perfil(email=email, hashed_password=hashed, role="admin", status="ativo")
            db.add(user)
        else:
            user.role = "admin"
            user.status = "ativo"
            user.hashed_password = hashed
        
        # 2. Define a senha global do sistema (usada no login do painel)
        cfg = db.query(ConfiguracaoSegura).filter(ConfiguracaoSegura.chave == "admin_activation_hash").first()
        if not cfg:
            cfg = ConfiguracaoSegura(chave="admin_activation_hash", valor_hash=hashed)
            db.add(cfg)
        else:
            cfg.valor_hash = hashed
        
        db.commit()
        print(f"\n✅ Administrador {email} configurado e ativado com sucesso!")

if __name__ == "__main__":
    setup_first_admin()