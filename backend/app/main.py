from __future__ import annotations

import os
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .log_analysis import analyze_logs
from .schemas import AnalyzeRequest, AnalyzeResponse

app = FastAPI(title="LogAnalyzer Agent", version="0.1.0")

cors_origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "*").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"] ,
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(payload: AnalyzeRequest):
    result = analyze_logs(payload.text, log_type_hint=payload.log_type, mode=payload.mode)
    return result


@app.post("/analyze-file", response_model=AnalyzeResponse)
async def analyze_file(
    file: UploadFile = File(...),
    log_type: str | None = Form(None),
    mode: str = Form("standard"),
):
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    result = analyze_logs(text, log_type_hint=log_type, mode=mode)
    return JSONResponse(result)
