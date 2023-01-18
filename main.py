from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from routers import (todo, auth)
from schemas import SuccessMsg, CsrfSettings
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError


# fastapiのインスタンス化
app = FastAPI()
# ↑のインスタンス設定に追加したい場合
app.include_router(todo.router)
app.include_router(auth.router)

# front end のドメインを記載
origins = ["https://localhost:3000"]
# CORSの設定をappに追加
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# セキュリティ対策の初期設定（ライブラリ参照）
@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()

@app.exception_handler(CsrfProtectError)
def csrf_protect_exception_handler(request: Request, exc: CsrfProtectError):
    return JSONResponse(
        status_code=exc.status_code,
        content={ 'detail':  exc.message
        }
    )

# エンドポイントの指定 (＠でデコレータ使用：パスを起動する際、直下関数起動) 
@app.get("/", response_model=SuccessMsg)
def root():
    return {"message": "Welcome to Fast API"}