import os

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from ..services.raml_service import analyze_apk_with_raml

router = APIRouter(prefix="/analysis", tags=["analysis"])

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@router.post("/upload")
async def upload_apk(file: UploadFile = File(...)):
    filename = file.filename or ""
    if not filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only APK files allowed")

    apk_path = os.path.join(UPLOAD_DIR, filename)
    with open(apk_path, "wb") as f:
        f.write(await file.read())

    result = await analyze_apk_with_raml(apk_path)
    return JSONResponse(content=result)
