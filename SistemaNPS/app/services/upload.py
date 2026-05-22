import base64
import mimetypes
import os
import uuid
from pathlib import Path


def upload_pdf(data_or_path: str, folder_or_path: str) -> str:
    """
    Recebe base64 (data:...;base64,...) ou caminho de arquivo local.
    Salva o arquivo no disco local (preparado para Magalu Cloud).
    Retorna o caminho relativo para persistência no banco.
    """
    try:
        # ---------------------------------
        # 1. Bytes e content-type
        # ---------------------------------
        content_type = None
        file_bytes = None

        if os.path.isfile(data_or_path):
            with open(data_or_path, "rb") as f:
                file_bytes = f.read()
            content_type, _ = mimetypes.guess_type(data_or_path)
        else:
            if "," in data_or_path and data_or_path.strip().lower().startswith("data:"):
                header, b64 = data_or_path.split(",", 1)
                if ";" in header:
                    content_type = header.split(":", 1)[1].split(";", 1)[0]
                file_bytes = base64.b64decode(b64)
            else:
                file_bytes = base64.b64decode(data_or_path)

        if not file_bytes:
            raise Exception("Arquivo vazio ou invalido")

        if not content_type:
            content_type = "application/pdf"

        # ---------------------------------
        # 2. Path remoto
        # ---------------------------------
        if folder_or_path.lower().endswith((".pdf", ".png", ".jpg", ".jpeg")):
            path = folder_or_path
        else:
            ext = ".pdf"
            if content_type == "image/png":
                ext = ".png"
            elif content_type == "image/jpeg":
                ext = ".jpg"
            filename = f"{uuid.uuid4()}{ext}"
            path = f"{folder_or_path}/{filename}"

        # Cria os diretórios se não existirem
        base_path = Path("app/static/uploads")
        full_dir = base_path / folder_or_path
        full_dir.mkdir(parents=True, exist_ok=True)
        
        final_file_path = full_dir / Path(path).name
        
        with open(final_file_path, "wb") as f:
            f.write(file_bytes)

        # Retorna o caminho iniciando com /app para compatibilidade com _download_pdf
        return f"/app/static/uploads/{path}"

    except Exception as e:
        raise Exception(f"Falha no upload: {str(e)}")
