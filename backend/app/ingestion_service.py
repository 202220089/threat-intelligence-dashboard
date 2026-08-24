from __future__ import annotations

from fastapi.encoders import jsonable_encoder
from sqlalchemy import insert, select

from .db import engine
from .log_parser import parse_log
from .tables import logs


class IngestionError(ValueError):
    pass


async def ingest(
    log_format: str,
    raw_message: str,
    detector=None,
) -> tuple[dict, list[dict]]:
    try:
        parsed = parse_log(log_format, raw_message)
    except ValueError as exc:
        raise IngestionError(str(exc)) from exc

    with engine.begin() as connection:
        result = connection.execute(insert(logs).values(**parsed))
        log_id = result.inserted_primary_key[0]
        row = connection.execute(
            select(logs).where(logs.c.id == log_id)
        ).mappings().one()

    log_payload = jsonable_encoder(dict(row))
    alerts = []

    if detector is not None:
        alerts = await detector.evaluate(log_id, parsed)

    return log_payload, alerts
