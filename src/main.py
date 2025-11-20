from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import Base, engine
from .routes import user_routes, analysis_routes

Base.metadata.create_all(bind=engine)

app = FastAPI(title="FastAPI Auth Service", root_path="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(user_routes.router)
app.include_router(analysis_routes.router)

@app.get("/")
def root():
    return {"message": "FastAPI Auth Backend Running"}
