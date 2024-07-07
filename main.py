from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

SECREET_KEY = "GOKULAKANNAN"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_IN_MINS = 30

app = FastAPI()

db = {
    "senthil" : {
        "username": "senthil",
        "full_name": "Senthilnathan",
        "email": "ssenthil1490@gmail.com",
        "hashed_password": "",
        "disabled": False
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str or None = None

class User(BaseModel):
    username: str
    email: str
    full_name: str or None = None
    disabled: bool or None = None


class UserInDB(BaseModel):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="TOKEN")


def verify(password, hashed_password):
    return pwd_context.verify(password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify(password, user.hashed_password):
        return False
    return user


def create_access_token(data: str, expires_in: timedelta or None = None):
    to_encode = data.copy()
    if expires_in:
        expire = datetime.utcnow() + expires_in
    else:
        expire = datetime.utcnow() + timedelta(mXinutes=15)
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECREET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth_2_scheme)):
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credential", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECREET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credential_exception
    
        token_data = TokenData(username=username)
    except JWTError:
        raise credential_exception

    user = get_user(db, username=token_data.username)
    
    if user is None:
        return credential_exception

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="User is inactive")
    return current_user


@app.post('/token', response_model=Token)
async def get_login_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, details="Unauthorized", headers={"WWW-Authenticate": "Bearer"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_IN_MINS)
    access_token = create_access_token(data={"sub": user.username}, expires_in=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}
    
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get("/users/items/me", response_model=User)
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{'item_id': 1, "owner": current_user}]
