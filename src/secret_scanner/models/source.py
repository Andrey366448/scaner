from __future__ import annotations

from pydantic import BaseModel


class SourceSpan(BaseModel):
    path: str
    line_start: int
    line_end: int
    col_start: int | None = None
    col_end: int | None = None
    commit: str | None = None


class SourceFragment(BaseModel):
    span: SourceSpan
    content: str
    language: str | None = None
    file_type: str | None = None
    is_binary: bool = False
