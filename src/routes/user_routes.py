from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from .. import schemas
from ..database import get_db
from ..services import user_service

router = APIRouter(prefix="/user", tags=["Users"])


@router.post("/register")
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    return user_service.register_user(user, db)


@router.post("/login")
def login_user(user: schemas.UserLogin, db: Session = Depends(get_db)):
    return user_service.login_user(user, db)
