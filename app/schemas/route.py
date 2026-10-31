# app/schemas/route.py
from typing import List, Optional
from pydantic import BaseModel, Field


class RouteParameter(BaseModel):
    name: str = Field(..., description="Parameter name, e.g., 'q', 'order_id', 'email'")
    source: str = Field(..., description="'query' | 'body' | 'path' | 'header' | 'cookie'")
    line: int = Field(..., description="1-based line number where the parameter is read")


class CalleeScope(BaseModel):
    function_name: str = Field(..., description="Name of the called helper function")
    file: str = Field(..., description="Relative POSIX path to the file defining or calling the function")
    call_line: int = Field(..., description="1-based line number inside the route handler where the call occurs")
    start_line: Optional[int] = Field(None, description="1-based start line of the helper function definition")
    end_line: Optional[int] = Field(None, description="1-based end line of the helper function definition")


class NormalizedRoute(BaseModel):
    raw_url: str = Field(..., description="Framework route string, e.g., '/api/orders/<int:order_id>'")
    normalized_url: str = Field(..., description="Canonical template, e.g., '/api/orders/{param}'")
    method: str = Field(..., description="Uppercase HTTP method: GET, POST, PUT, DELETE, PATCH")
    handler_function: str = Field(..., description="Function name handling the endpoint")
    file: str = Field(..., description="Relative POSIX path to the handler source file")
    start_line: int = Field(..., description="1-based start line of the handler function")
    end_line: int = Field(..., description="1-based end line of the handler function")
    middlewares: List[str] = Field(default_factory=list, description="Attached auth/validation middlewares")
    parameters: List[RouteParameter] = Field(default_factory=list, description="Extracted HTTP inputs")
    callees: List[CalleeScope] = Field(default_factory=list, description="1-hop called helper functions")
