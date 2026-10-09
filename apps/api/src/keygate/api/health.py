"""Health endpoints.

* ``GET /health``       liveness: the process is up. No dependencies, so a database
                        outage doesn't make the orchestrator restart healthy API containers.
* ``GET /health/ready`` readiness: Postgres and Redis are reachable.

Responses reveal only ``ok``/``unavailable`` per dependency, never error messages,
hostnames or versions.
"""

import asyncio
from typing import Literal

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from keygate.logging_setup import get_logger

router = APIRouter(prefix="/health", tags=["health"])
log = get_logger(__name__)

CheckStatus = Literal["ok", "unavailable"]
CHECK_TIMEOUT_SECONDS = 2.0


class LivenessResponse(BaseModel):
    status: Literal["ok"] = "ok"


class ReadinessResponse(BaseModel):
    status: Literal["ok", "degraded"]
    checks: dict[str, CheckStatus]


async def check_database(engine: AsyncEngine) -> CheckStatus:
    try:
        async with asyncio.timeout(CHECK_TIMEOUT_SECONDS), engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:
        log.warning("readiness_check_failed", dependency="database", error_type=type(exc).__name__)
        return "unavailable"
    return "ok"


async def check_redis(redis: "Redis") -> CheckStatus:
    try:
        async with asyncio.timeout(CHECK_TIMEOUT_SECONDS):
            await redis.ping()
    except Exception as exc:
        log.warning("readiness_check_failed", dependency="redis", error_type=type(exc).__name__)
        return "unavailable"
    return "ok"


@router.get("", response_model=LivenessResponse)
async def liveness() -> LivenessResponse:
    return LivenessResponse()


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    responses={503: {"model": ReadinessResponse}},
)
async def readiness(request: Request, response: Response) -> ReadinessResponse:
    db_status, redis_status = await asyncio.gather(
        check_database(request.app.state.engine),
        check_redis(request.app.state.redis),
    )
    checks: dict[str, CheckStatus] = {"database": db_status, "redis": redis_status}
    healthy = all(v == "ok" for v in checks.values())
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(status="ok" if healthy else "degraded", checks=checks)
