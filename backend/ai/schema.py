"""Strict shape of what the model may return. Anything else is rejected, never trusted."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SEVERITIES = ("info", "low", "medium", "high", "critical")
Severity = Literal["info", "low", "medium", "high", "critical"]


class Triage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity
    summary: str = Field(min_length=1, max_length=300)
    recommended_action: str = Field(min_length=1, max_length=300)


def json_schema() -> dict:
    """Schema handed to the model (Ollama 'format' accepts a JSON schema)."""
    return Triage.model_json_schema()
