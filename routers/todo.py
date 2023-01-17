# routerの有効化
from fastapi import APIRouter, Request, Response, HTTPException, Depends
from schemas import Todo, TodoBody, SuccessMsg
from fastapi.encoders import jsonable_encoder
from database import db_create_todo, db_get_todos, db_get_single_todo, db_update_todo, db_delete_todo
from starlette.status import HTTP_201_CREATED
from typing import List
from fastapi_csrf_protect import CsrfProtect
from auth_utils import AuthJwtCsrf

router = APIRouter()
auth = AuthJwtCsrf()

# タスクを追加するエンドポイント
# =Todoはschemas.pyで指定した型
@router.post("/api/todo", response_model=Todo)
async def create_todo(request: Request, response: Response, data: TodoBody, csrf_protect: CsrfProtect = Depends()):
    # 新しいアップデートしてjwtトークンの取得
    new_token = auth.verify_csrf_update_jwt(request, csrf_protect, request.headers)
    # dataはjson型で渡ってくる為、dict型に変換する
    todo = jsonable_encoder(data)
    res = await db_create_todo(todo)
    response.status_code = HTTP_201_CREATED
    # 新しいjwtの情報にcookieを書き換える
    response.set_cookie(key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True)
    # dataは辞書型かFalseで返ってくる為、データ有無を調査
    if res:
        return res
    raise HTTPException(
        status_code=404,
        detail="Create task failed"
    )

# タスク一覧を取得するエンドポイント
@router.get("/api/todo", response_model=List[Todo])
async def get_todos(request: Request):
    # jwtの検証
    # auth.verify_jwt(request)
    res = await db_get_todos()
    return res

# IDで一つのtodoを取得するエンドポイント
@router.get("/api/todo/{id}", response_model=Todo)
async def get_single_todo(id: str, request: Request, response: Response):
    new_token, _ = auth.verify_update_jwt(request)
    res = await db_get_single_todo(id)
    # jwtの書き換え
    response.set_cookie(key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True)
    
    if res:
        return res
    raise HTTPException(
        status_code=404,
        detail=f"Task of ID:{id} doesn't exist"
    )

# updateのtodoを取得するエンドポイント
@router.put("/api/todo/{id}", response_model=Todo)
# 保守の仕組みはcreateと同様
async def update_todo(id: str, data: TodoBody, request: Request, response: Response, csrf_protect: CsrfProtect = Depends()):
    # 新しいアップデートしてjwtトークンの取得
    new_token = auth.verify_csrf_update_jwt(request, csrf_protect, request.headers)
    todo = jsonable_encoder(data)
    res = await db_update_todo(id, todo)
    response.set_cookie(key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True)
    if res:
        return res
    raise HTTPException(
        status_code=404,
        detail="Update task failed"
    )

# deletするエンドポイント
@router.delete("/api/todo/{id}", response_model=SuccessMsg)
async def delete_todo(id: str, request: Request, response: Response, csrf_protect: CsrfProtect = Depends()):
    new_token = auth.verify_csrf_update_jwt(request, csrf_protect, request.headers)
    res = await db_delete_todo(id)
    response.set_cookie(key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True)
    if res:
        return {"message": "Successfully deleted"}
    raise HTTPException(
        status_code=404,
        detail="Delete task failed"
    )
