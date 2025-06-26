from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta, timezone
import redis.asyncio as redis
import uvicorn

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
redis_client = None

SECRET_KEY = "65626326523652363"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@app.on_event("startup")
async def startup():
    global redis_client
    redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/register/")
async def register_user(user: dict):
    key = f"user:{user['username']}"
    if await redis_client.exists(key):
        raise HTTPException(status_code=400, detail="User exists")
    user_data = {
        "username": user["username"],
        "email": user["email"],
        "full_name": user.get("full_name", ""),
        "hashed_password": get_password_hash(user["password"]),
        "disabled": "false"
    }
    await redis_client.hset(key, mapping=user_data)
    del user_data["hashed_password"]
    return user_data

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    key = f"user:{form_data.username}"
    if not await redis_client.exists(key):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user = await redis_client.hgetall(key)
    if not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/users/")
async def get_users():
    keys = await redis_client.keys("user:*")
    users = []
    for key in keys:
        user = await redis_client.hgetall(key)
        user.pop("hashed_password", None)
        users.append(user)
    return users


if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)
