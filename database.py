from decouple import config
import motor.motor_asyncio
from bson import ObjectId
import os
from dotenv import load_dotenv
from auth_utils import AuthJwtCsrf
from fastapi import HTTPException
import asyncio

# 環境変数の読み込み
load_dotenv()
MONGO_API_KEY = os.environ['MONGO_API_KEY']

# クライアント作成
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_API_KEY)
client.get_io_loop = asyncio.get_event_loop #<-追加

# databaseとコレクションをAPIで使用出来る様にする
# mongoDBでcreateしたDBを指定
database = client.API_DB
# DBのコレクション名を指定
collection_todo = database.todo
collection_user = database.user

# 認証のインスタンス化
auth = AuthJwtCsrf()

# mongoDBから取れたデータを辞書型に変換する必要がある
#   (idがバイナリ形式で返ってくるため)
def todo_serializer(todo):
    return {
        "id" : str(todo["_id"]),
        "title": todo["title"],
        "description": todo["description"]
    }

# mongoDBに対してタスクのdatasetを作成
async def db_create_todo(data: dict):
    # タスクを追加する: defaultでinserted_idが追加順に付く
    todo = await collection_todo.insert_one(data)
    new_todo = await collection_todo.find_one({"_id": todo.inserted_id})
    # documentの有無
    if new_todo:
        return todo_serializer(new_todo)
    return False

# タスク(document)の一覧を取得する
async def db_get_todos():
    todos = []
    for todo in await collection_todo.find().to_list(length=100):
        todos.append(todo_serializer(todo))
    return todos

# ID指定でtodoを取得する
    # ObjectId(id) : mongoDBから取れたデータを辞書型に変換する必要がある
    #   (バイナリ形式で返ってくるため)
async def db_get_single_todo(id: str):
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if todo:
        return todo_serializer(todo)
    return False

# documentを更新する
async def db_update_todo(id: str, data: dict):
    # 引数で受け取ったidがdatabaseに存在するか検証
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if todo:
        update_todo = await collection_todo.update_one(
            {"_id": ObjectId(id)}, {"$set": data}
        )
        # 0より大きい場合は更新に成功
        # update後のtodoを取得する
        if update_todo.modified_count > 0:
            new_todo = await collection_todo.find_one({"_id": ObjectId(id)})
            return todo_serializer(new_todo)
    return False

# todoの削除
async def db_delete_todo(id: str):
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if todo:
        delet_todo = await collection_todo.delete_one(
            {"_id": ObjectId(id)}
        )
        if delet_todo.deleted_count > 0:
            return True
    return False

# ===========================================================================================

# idはオブジェクトになっている為、strに変換して全てオブジェクトで返すようにする
def user_serializer(user):
    return {
        "id" : str(user["_id"]),
        "email": user["email"],
    }

# userを新規に作成する関数
async def db_signup(data) -> dict:
    # userが入力したもの
    email = data.get("email")
    password = data.get("password")

    # メールの存在を確認
    overlap_user = await collection_user.find_one({"email": email})
    if overlap_user:
        raise HTTPException(status_code=400, detail="Email is already taken")
    
    # passwordチェック (未入力 or 6文字以下はエラーにする)
    if not password or len(password) < 6:
        raise HTTPException(status_code=400, detail="Password too short")
    
    # userを作成
    user = await collection_user.insert_one({
        "email": email,
        "password": auth.generate_hashed_pw(password)
    })

    # userが作成されると自動的にidを付与される(key= inserted_id)
    new_user = await collection_user.find_one({"_id": user.inserted_id})
    return user_serializer(new_user)


# ログイン関数
async def db_login(data) -> str:
    email = data.get("email")
    password = data.get("password")
    user = await collection_user.find_one({"email": email})
    # 未入力または、db内のパスワードと一致しない場合
    if not user or not auth.verify_pw(password, user["password"]):
        raise HTTPException(
            status_code=401, detail="Invalid email or password"
        )
    # 問題なければメールを渡して、JWTのtokenを返す
    token = auth.encode_jwt(user["email"])
    return token