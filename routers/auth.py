from fastapi import APIRouter
from fastapi import Request, Response, Depends
from fastapi.encoders import jsonable_encoder
from schemas import UserBody, SuccessMsg, UserInfo, Csrf
from database import db_signup, db_login
from auth_utils import AuthJwtCsrf
from fastapi_csrf_protect import CsrfProtect

router = APIRouter()
auth = AuthJwtCsrf()

# csrfトークン生成の為のエンドポイント
@router.get("/api/csrftoken", response_model=Csrf)
def get_csrf_token(csrf_protect: CsrfProtect = Depends()):
    # csrfトークンの取得
    csrf_token = csrf_protect.generate_csrf()
    res = {"csrf_token": csrf_token}
    return res


# 入力のエンドポイント(CSRFの検証)
@router.post("/api/register", response_model=UserInfo)
async def siginup(user: UserBody, request: Request, csrf_protect: CsrfProtect = Depends()):
    # headerからトークンを取得
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.validate_csrf(csrf_token)
    user = jsonable_encoder(user)
    new_user = await db_signup(user)
    return new_user


# ログインのエンドポイント(CSRFの検証)
@router.post("/api/login", response_model=SuccessMsg)
async def login(response: Response, user: UserBody, request: Request, csrf_protect: CsrfProtect = Depends()):
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.validate_csrf(csrf_token)
    user = jsonable_encoder(user)
    token = await db_login(user)
    # XSS対策でcookieを設定
    response.set_cookie(
        key="access_token", 
        value=f"Bearer {token}",
        httponly=True,
        samesite="none",
        secure=True
    )
    return {"message": "Successfully logged-in"}


# ログアウトのエンドポイント(CSRFの検証)
@router.post("/api/logout", response_model=SuccessMsg)
def logout(response: Response, request: Request, csrf_protect: CsrfProtect = Depends()):
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.validate_csrf(csrf_token)
    # cookeのjwtを空にする
    response.set_cookie(key="access_token", value="", httponly=True, samesite="none", secure=True)
    return {"message": "Successfully logged-out"}


# user作成のエンドポイント(jwtの検証とリフレッシュ)
@router.get("/api/user", response_model=UserInfo)
def get_user_refresh_jwt(response: Response, request: Request):
    new_token, subject = auth.verify_update_jwt(request)
    response.set_cookie(key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True)
    return {"email": subject}