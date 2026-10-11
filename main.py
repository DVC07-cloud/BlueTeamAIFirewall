"""FastAPI front door for the Blue-Team AI firewall.

Run:  uvicorn main:app --reload
      curl -X POST localhost:8000/analyze -H 'content-type: application/json' \
           -d '{"message": "send 500 to Rahul for rent"}'

Set FIREWALL_USE_LLM=1 and GEMINI_API_KEY=... to enable the Gemini layer.
"""
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict

from firewall_engine import Firewall, execute_mock

app = FastAPI(title="Blue-Team AI Firewall")
firewall = Firewall()


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    message: Any = None   # accept anything; the firewall decides (fail closed)


@app.get("/", include_in_schema=False)
def demo_page() -> FileResponse:
    return FileResponse(Path(__file__).parent / "demo.html")


@app.post("/analyze")
def analyze(body: AnalyzeRequest) -> dict:
    """Firewall verdict only. No tool is ever executed here."""
    return firewall.analyze(body.message).model_dump(mode="json")


@app.post("/request")
def request(body: AnalyzeRequest) -> dict:
    """Full banking flow: firewall first, mock tool only if APPROVED."""
    result = firewall.analyze(body.message)
    out: dict = {"firewall": result.model_dump(mode="json"), "execution": None}
    if result.status.value == "APPROVED":
        out["execution"] = execute_mock(result)
    return out


@app.get("/health")
def health() -> dict:
    return {"ok": True, "llm_layer": firewall.use_llm}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
