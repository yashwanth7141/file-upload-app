import bcrypt
from app.db.models.user import User
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from fastapi import HTTPException
from app.db.models.user import User
import bcrypt
from jose import jwt, JWTError
from app.schemas.user_model import login 
from app.db.database import get_db
from app.core.utils import verify_password
from fastapi import Request, Depends, HTTPException
from jose import jwt, JWTError


SECRET_KEY = "MOBILE_APP"  # move to env var in real apps
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

#function to hash the password
def hash_password(password: str) -> str:
    
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

async def user_creation(user_data, db):
    db_user = User(
        fullname=user_data.fullname,
        username=user_data.username,
        email=user_data.email,
        phone_number=user_data.phone_number,
        is_active=True,
        hashed_password=hash_password(user_data.password),
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user




async def user_login_function(user_data: login, db: Session):
    user = db.query(User).filter(User.username == user_data.username).first()

    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    user.is_active = True
    db.commit()
    db.refresh(user)
    
    access_token = create_access_token(
        data={
            "sub": user.username,
            "id": user.id
            },
        # expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }




async def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
):
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    try:
        scheme, token = auth_header.split(" ")
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid auth scheme")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user

    

async def user_logout(db):
    ''' API to logout the user. '''
    try:
        result = db.query(User).filter(User.is_active == True).update({"is_active": False})
        db.commit() 
        return result
    except Exception as e:
        db.rollback()
        raise e