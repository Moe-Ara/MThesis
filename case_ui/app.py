import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles


ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"

app = FastAPI(title="Case Dashboard", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _db_path() -> Path:
    return Path(os.environ.get("CASE_DB_PATH", "data/cases.db"))


def _connect() -> Tuple[Optional[sqlite3.Connection], Optional[str]]:
    path = _db_path()
    if not path.exists():
        return None, f"Case DB not found: {path}"
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn, None


def _read_json(raw: Optional[str]) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _fetch_cases(limit: int = 200) -> Dict[str, Any]:
    conn, err = _connect()
    if err:
        return {"ok": False, "message": err, "cases": []}

    try:
        cur = conn.execute(
            """
            SELECT CaseId, CreatedAtUtc, UpdatedAtUtc, Status, Severity, Summary, CorrelationId, AlertKey
            FROM Cases
            ORDER BY UpdatedAtUtc DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        return {"ok": True, "cases": rows}
    finally:
        conn.close()


def _fetch_case(case_id: str) -> Dict[str, Any]:
    conn, err = _connect()
    if err:
        return {"ok": False, "message": err}

    try:
        cur = conn.execute(
            """
            SELECT CaseId, CreatedAtUtc, UpdatedAtUtc, Status, Severity, Summary, CorrelationId, AlertKey
            FROM Cases
            WHERE CaseId = ?
            """,
            (case_id,),
        )
        row = cur.fetchone()
        if row is None:
            return {"ok": False, "message": "Case not found"}

        case = dict(row)
        cur = conn.execute(
            """
            SELECT EventId, CaseId, TimestampUtc, Type, Message, DataJson
            FROM CaseEvents
            WHERE CaseId = ?
            ORDER BY TimestampUtc DESC
            """,
            (case_id,),
        )
        events = []
        for r in cur.fetchall():
            item = dict(r)
            item["data"] = _read_json(item.pop("DataJson", None))
            events.append(item)

        return {"ok": True, "case": case, "events": events}
    finally:
        conn.close()


def _fetch_stats() -> Dict[str, Any]:
    conn, err = _connect()
    if err:
        return {"ok": False, "message": err, "stats": {}}

    try:
        cur = conn.execute(
            "SELECT Status, COUNT(*) AS Count FROM Cases GROUP BY Status"
        )
        stats = {row["Status"]: row["Count"] for row in cur.fetchall()}
        total = sum(stats.values()) if stats else 0
        stats["Total"] = total
        return {"ok": True, "stats": stats}
    finally:
        conn.close()


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/cases")
def list_cases(limit: int = 200) -> JSONResponse:
    return JSONResponse(_fetch_cases(limit=limit))


@app.get("/api/cases/{case_id}")
def case_detail(case_id: str) -> JSONResponse:
    return JSONResponse(_fetch_case(case_id))


@app.get("/api/stats")
def case_stats() -> JSONResponse:
    return JSONResponse(_fetch_stats())


def main() -> None:
    import uvicorn

    host = os.environ.get("CASE_UI_HOST", "127.0.0.1")
    port = int(os.environ.get("CASE_UI_PORT", "8100"))
    uvicorn.run("case_ui.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
