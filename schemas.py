from pydantic import BaseModel
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()
CSRF_KEY = os.environ['CSRF_KEY']

class CsrfSettings(BaseModel):
    secret_key: str = CSRF_KEY

# 返してくれるデ―タ型の指定
class Todo(BaseModel):
    id: str
    title: str
    description: str

# データの型を形成
class TodoBody(BaseModel):
    title: str
    description: str

# 成功時のメッセージ型
class SuccessMsg(BaseModel):
    message: str

# user認証の型指定
class UserBody(BaseModel):
    email: str
    password: str

# レスポンスの型指定
class UserInfo(BaseModel):
    email: str
    id: Optional[str] = None

# CSRF token 生成型の指定
class Csrf(BaseModel):
    csrf_token: str

