"""Shared pieces of the HTTP API: errors, dependencies, role checks.

Errors always have the shape::

    {"error": "<code>", "message": "<english text>", "params": {...}, "issues": [...]}

The UI translates ``error`` and each issue ``code``; ``message`` is a
fallback for codes it does not know.
"""
from __future__ import annotations

import sqlite3
from typing import Iterator

from fastapi import Depends, HTTPException, Request

from .. import db
from ..core.auth import Principal
from ..seclang.model import Issue


class ApiError(HTTPException):
    def __init__(self, status: int, code: str, message: str = "", issues: list | None = None,
                 **params):
        super().__init__(status_code=status, detail=code)
        self.code = code
        self.message = message or code.replace("_", " ")
        self.params = params
        self.issues = issues or []

    def body(self) -> dict:
        return {"error": self.code, "message": self.message, "params": self.params,
                "issues": self.issues}


def issues_json(issues: list[Issue]) -> list[dict]:
    return [{"field": i.field, "code": i.code, "level": i.level, "params": i.params} for i in issues]


def get_conn() -> Iterator[sqlite3.Connection]:
    with db.db() as conn:
        yield conn


def principal(request: Request) -> Principal:
    p = getattr(request.state, "principal", None)
    if p is None:
        raise ApiError(401, "not_authenticated", "log in first")
    return p


def require(role: str):
    def dep(p: Principal = Depends(principal)) -> Principal:
        if not p.can(role):
            raise ApiError(403, "forbidden", f"this action needs the {role} role", role=role)
        return p
    return dep


viewer = require("viewer")
editor = require("editor")
admin = require("admin")


def actor(p: Principal) -> str:
    return p.username
