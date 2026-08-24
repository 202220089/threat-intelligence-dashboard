from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select

from .analytics import recent_threats, threat_stats, timeline, top_sources
from .config import settings
from .db import engine
from .ingestion_service import IngestionError, ingest
from .ip_intelligence import add_to_blacklist, ip_info
from .schemas import BlacklistRequest, IngestLogRequest, PfsenseLogRequest
from .tables import logs, threat_alerts
from .threat_detector import ThreatDetector
from .websocket_manager import ConnectionManager


app = FastAPI(
    title="Threat Intelligence Dashboard API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        value.strip()
        for value in settings.cors_origins.split(",")
        if value.strip()
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

manager = ConnectionManager()


async def broadcast(event: str, data: dict) -> None:
    await manager.broadcast(event, data)


detector = ThreatDetector(broadcast)


@app.get("/health")
def health():
    with engine.connect() as connection:
        connection.execute(select(func.now()))
    return {"status": "ok"}


@app.post("/api/ingest/log", status_code=201)
async def ingest_log(request: IngestLogRequest):
    try:
        log_payload, alerts = await ingest(
            request.format,
            request.raw_message,
            detector,
        )
    except IngestionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "log": log_payload,
        "alerts": jsonable_encoder(alerts),
    }


@app.get("/api/logs/recent")
def get_recent_logs(limit: int = Query(default=100, ge=1, le=500)):
    statement = (
        select(logs)
        .order_by(logs.c.timestamp.desc())
        .limit(limit)
    )
    with engine.connect() as connection:
        rows = connection.execute(statement).mappings().all()
    return jsonable_encoder([dict(row) for row in rows])


@app.get("/api/threats")
def get_threats(
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    from_date: datetime | None = None,
    to_date: datetime | None = None,
):
    return jsonable_encoder(recent_threats(severity, from_date, to_date))


@app.get("/api/threats/stats")
def get_threat_stats():
    return jsonable_encoder(threat_stats())


@app.get("/api/threats/{threat_id}")
def get_threat(threat_id: int):
    statement = (
        select(
            threat_alerts.c.id,
            threat_alerts.c.log_id,
            threat_alerts.c.threat_type,
            threat_alerts.c.threat_score,
            threat_alerts.c.description,
            threat_alerts.c.is_resolved,
            threat_alerts.c.created_at,
            logs.c.timestamp.label("log_timestamp"),
            logs.c.source_ip,
            logs.c.destination_ip,
            logs.c.event_type,
            logs.c.raw_message,
            logs.c.parsed_data,
        )
        .select_from(threat_alerts.join(logs, threat_alerts.c.log_id == logs.c.id))
        .where(threat_alerts.c.id == threat_id)
    )

    with engine.connect() as connection:
        row = connection.execute(statement).mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="Threat not found")

    return jsonable_encoder(dict(row))


@app.post("/api/threats/{threat_id}/resolve")
def resolve_threat(threat_id: int):
    with engine.begin() as connection:
        result = connection.execute(
            threat_alerts.update()
            .where(threat_alerts.c.id == threat_id)
            .values(is_resolved=True)
        )

        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Threat not found")

        row = connection.execute(
            select(threat_alerts).where(threat_alerts.c.id == threat_id)
        ).mappings().one()

    return jsonable_encoder(dict(row))


@app.get("/api/analytics/timeline")
def get_timeline(
    interval: Literal["minute", "hour", "day"] = "hour",
    range_value: str = Query("24h", alias="range"),
):
    try:
        return jsonable_encoder(timeline(interval, range_value))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/analytics/top-sources")
def get_top_sources(limit: int = Query(default=10, ge=1, le=100)):
    return jsonable_encoder(top_sources(limit))


@app.get("/api/ip/{ip_address}/info")
def get_ip_info(ip_address: str):
    try:
        return jsonable_encoder(ip_info(ip_address))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/ip/blacklist", status_code=201)
def blacklist_ip(request: BlacklistRequest):
    try:
        return jsonable_encoder(
            add_to_blacklist(
                request.ip_address,
                request.reason,
                request.source,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/ingest/pfsense", status_code=201)
async def ingest_pfsense(request: PfsenseLogRequest):
    try:
        log_payload, alerts = await ingest(
            "pfsense",
            request.raw_message,
            detector,
        )
    except IngestionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "log": log_payload,
        "alerts": jsonable_encoder(alerts),
    }


@app.get("/api/pfsense/firewall-rules")
def firewall_rule_stats():
    with engine.connect() as connection:
        rows = connection.execute(
            select(logs.c.timestamp, logs.c.parsed_data)
            .where(logs.c.event_type == "firewall_block")
        ).all()

    counts: dict[str, int] = {}
    latest: dict[str, datetime] = {}

    for timestamp, parsed_data in rows:
        data = parsed_data if isinstance(parsed_data, dict) else {}
        rule_id = str(data.get("firewall_rule", "unknown"))
        counts[rule_id] = counts.get(rule_id, 0) + 1
        if rule_id not in latest or timestamp > latest[rule_id]:
            latest[rule_id] = timestamp

    result = [
        {
            "rule_id": rule_id,
            "hit_count": count,
            "last_hit": latest[rule_id],
        }
        for rule_id, count in counts.items()
    ]
    result.sort(key=lambda item: item["hit_count"], reverse=True)
    return jsonable_encoder(result)


@app.websocket("/ws/logs")
async def logs_websocket(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
