from sqlalchemy.orm import Session
from fastapi import HTTPException
from passlib.context import CryptContext
from .. import models, schemas

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def register_user(user: schemas.UserCreate, db: Session):
    existing_user = db.query(models.User).filter(models.User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    password = user.password.strip()[:72] 
    hashed_pw = pwd_context.hash(password)
    new_user = models.User(username=user.username, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "Registration successful"}


def login_user(user: schemas.UserLogin, db: Session):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if not db_user or not pwd_context.verify(user.password, str(db_user.hashed_password)):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    return {"message": "Login successful"}
