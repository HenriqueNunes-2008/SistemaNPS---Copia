from fastapi import FastAPI, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from urllib.parse import quote_plus
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env (como a DATABASE_URL)
load_dotenv()

# Importa o engine e os modelos para disparar a criação automática das tabelas no PostgreSQL
from app.database import engine
from app import models

# Cria as tabelas no PostgreSQL se elas não existirem
models.Base.metadata.create_all(bind=engine)

# Imports diretos dos routers
from app.routers.public import router as public_router
from app.routers.nps import router as nps_router
from app.routers.termo import router as termo_router
from app.routers.ressalvas import router as ressalvas_router
from app.routers.processos import router as processos_router

app = FastAPI(title="Sistema NPS Simplificado")

# Static
app.mount("/static", StaticFiles(directory="app/static"), name="static")

templates = Jinja2Templates(directory="app/templates")

# Routers essenciais
app.include_router(public_router)
app.include_router(nps_router)
app.include_router(termo_router)
app.include_router(ressalvas_router)
app.include_router(processos_router)

# Redireciona a raiz para a página de login/admin
@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    return RedirectResponse(url="/admin-password")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
