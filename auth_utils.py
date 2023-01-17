import jwt
from fastapi import HTTPException
from passlib.context import CryptContext
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()
JWT_KEY = os.environ['JWT_KEY']

# 認証関係の処理をまとめたクラス
class AuthJwtCsrf():

    # パスワード生成とJWT
    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret_key = JWT_KEY

    # userがformに入力したパスワードを受け取りパスワードをハッシュ化する関数
    def generate_hashed_pw(self, password) -> str:
        return self.pwd_ctx.hash(password)

    # パスワードを検証する関数
    # userが入力したパスワードとDBに保存されているハッシュ化したパスワードを比較
    def verify_pw(self, user_pw, hash_pw) -> bool:
        return self.pwd_ctx.verify(user_pw, hash_pw)
    
    # jwtを実際に生成する関数
    def encode_jwt(self, email) -> str:
        payload = {
            # iwtの有効期限　（今回は生成された時間から＋5分間）
            "exp": datetime.utcnow() + timedelta(days=0, minutes=5),
            # jwtが生成された日時
            "iat": datetime.utcnow(),
            # ユーザーを一意に識別できる物　（今回はメール）
            "sub": email
        }
        return jwt.encode(
            payload,
            self.secret_key,
            algorithm="HS256"
        )

    # デコードして与えられたJWTを解析してくれる関数
    def decode_jwt(self, token) -> str:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=401, detail="the JWT has expired"
            )
        except jwt.InvalidTokenError as e:
            raise HTTPException(
                status_code=401, detail="JWT is not valid"
            )

    # JWTの有効性を検証する関数
    def verify_jwt(self, request) -> str:
        # jwt_token取得
        token = request.cookies.get("access_token")
        if not token:
            raise HTTPException(status_code=401, detail="No JWT exist: may not set yet or deleted")
        _, _, value = token.partition(" ") # valueのみを取り出す
        subject = self.decode_jwt(value)
        return subject
    
    # JWTを検証とupdateする関数
    def verify_update_jwt(self, request) -> tuple[str, str]:
        # 有効なら今回はメールが返ってくる
        subject = self.verify_jwt(request)
        # 新jwtの生成
        new_token = self.encode_jwt(subject)
        return new_token, subject

    # CARFトークンの検証とJWTトークンの検証 and JWTの更新
    def verify_csrf_update_jwt(self, request, csrf_protect, headers) -> str:
        # リクエストヘッダーからCSRFトークンを取り出す
        csrf_token = csrf_protect.get_csrf_from_headers(headers)
        csrf_protect.validate_csrf(csrf_token)
        # 例外処理がはしらなければCSRFトークンが有効とわかる為、jwtトークンの検証をする
        subject = self.verify_jwt(request)
        # 問題なければ、トークン生成
        new_token = self.encode_jwt(subject)
        return new_token