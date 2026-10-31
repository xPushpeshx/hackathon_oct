from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class TargetProfile(BaseModel):
    target_id: str
    scan_id: Optional[str] = None
    app_type: Literal["flask", "express"]
    source_path: str
    runtime_url: str
    language_adapter: str


class RouteInput(BaseModel):
    name: str
    location: Literal["query", "body", "path", "header", "cookie"]
    line: int


class HelperScope(BaseModel):
    file: str
    start_line: int
    end_line: int


class RouteNode(BaseModel):
    route_id: str
    target_id: str
    scan_id: Optional[str] = None
    path: str
    methods: list[str] = Field(default_factory=list)
    handler: str
    file: str
    start_line: int
    end_line: int
    helper_scopes: list[HelperScope] = Field(default_factory=list)
    inputs: list[RouteInput] = Field(default_factory=list)
    unresolved: bool = False


class UnifiedFinding(BaseModel):
    finding_id: str
    target_id: str
    scan_id: Optional[str] = None
    source_tool: Literal["semgrep", "zap"]
    tool_rule_id: str
    cwe: Optional[int] = None
    severity: str
    file: str
    line: int
    route: Optional[str] = None
    method: Optional[str] = None
    parameter: Optional[str] = None
    mapping_status: Literal["mapped", "ambiguous", "unmapped", "n/a"] = "n/a"
    candidate_routes: list[str] = Field(default_factory=list)
    evidence: str
    raw_ref: str


class CodeContextResult(BaseModel):
    finding_id: str
    route_id: str
    scan_id: Optional[str] = None
    score: float = 0.0
    model_name: str = "graphcodebert-base"
    model_revision: str = "pinned"
    preprocess_version: str = "v1"
    status: Literal["ok", "failed", "timeout", "skipped"] = "skipped"
    error: Optional[str] = None


class ScanTask(BaseModel):
    task_id: str
    target_id: str
    scan_id: Optional[str] = None
    route: str
    method: str
    input: str
    zap_rule_ids: list[str] = Field(default_factory=list)
    queue: Literal["focused", "broad"]
    priority: float = 0.0
    reason: str
    status: Literal["queued", "running", "completed", "failed", "skipped", "needs_auth", "unreachable"] = "queued"
    error: Optional[str] = None
    started_at: Optional[str] = None
    ended_at: Optional[str] = None


class CorrelationResult(BaseModel):
    sast_finding_id: str
    dast_finding_id: str
    criteria: dict
    label: Literal["Confirmed", "Code only", "Runtime only"]
    rationale: str


class SemgrepRunResult(BaseModel):
    status: Literal["ok", "failed"]
    findings: list[UnifiedFinding] = Field(default_factory=list)
    error: Optional[str] = None
