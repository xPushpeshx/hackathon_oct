# app/parsers/javascript_parser/express_route_mapper.py
from dataclasses import dataclass, field
from typing import Dict, List
from app.normalizer.route_normalizer import join_url_paths, normalize_static_path
from app.parsers.javascript_parser.ts_ast_parser import TSFunctionSymbol, TSProjectIndex


@dataclass
class RawExpressRoute:
    raw_url: str
    normalized_url: str
    method: str
    handler: TSFunctionSymbol
    middlewares: List[str] = field(default_factory=list)
    resolved: bool = True
    unresolved_reason: str | None = None


class ExpressRouteMapper:
    """Pass 2: Resolves Express router prefixes and maps routes to their target TSFunctionSymbol."""

    def extract_routes(self, index: TSProjectIndex) -> List[RawExpressRoute]:
        # Step 2A: Map router file -> mounted URL prefix (e.g. app.use('/rest/user', userRouter))
        file_prefixes: Dict[str, List[str | None]] = {}
        local_router_prefixes: Dict[tuple, List[str | None]] = {}

        for rel_path, file_ctx in index.files.items():
            for mount in file_ctx.mounts:
                prefix = mount["prefix"]
                target_router = mount["target_router"]

                if target_router in file_ctx.imports:
                    imp = file_ctx.imports[target_router]
                    target_file = index.resolve_import_target_file(rel_path, imp["from"])
                    if target_file:
                        file_prefixes.setdefault(target_file, []).append(
                            prefix if mount.get("resolved", True) else None
                        )
                else:
                    local_router_prefixes.setdefault(
                        (rel_path, target_router), []
                    ).append(prefix if mount.get("resolved", True) else None)

        # Step 2B: Resolve every discovered route registration
        discovered: List[RawExpressRoute] = []
        for rel_path, file_ctx in index.files.items():
            for route_entry in file_ctx.routes:
                router_name = route_entry["router"]
                prefixes = file_prefixes.get(rel_path, [""])
                local_prefixes = local_router_prefixes.get(
                    (rel_path, router_name), [""]
                )
                method = route_entry["method"]
                middlewares = route_entry.get("middlewares", [])

                # Resolve handler: inline arrow function OR imported/local symbol
                inline_data = route_entry.get("inline_handler")
                if inline_data:
                    handler_sym = TSFunctionSymbol(
                        name=inline_data["name"],
                        file=rel_path,
                        start_line=inline_data["start_line"],
                        end_line=inline_data["end_line"],
                        params=inline_data.get("params", []),
                        calls=inline_data.get("calls", []),
                    )
                else:
                    handler_ref = route_entry.get("handler_ref")
                    handler_sym = index.resolve_handler_symbol(rel_path, handler_ref)
                    if not handler_sym:
                        # Fallback to registration location if dynamic/external middleware
                        handler_sym = TSFunctionSymbol(
                            name=handler_ref or "anonymous_handler",
                            file=rel_path,
                            start_line=route_entry["line"],
                            end_line=route_entry["line"],
                        )

                methods = ["GET", "POST", "PUT", "DELETE", "PATCH"] if method == "ALL" else [method]
                for file_prefix in prefixes:
                    for local_prefix in local_prefixes:
                        resolved = file_prefix is not None and local_prefix is not None
                        path_parts = [
                            part
                            for part in (file_prefix, local_prefix, route_entry["path"])
                            if part
                        ]
                        full_raw_url = join_url_paths(*path_parts)
                        norm_url = normalize_static_path(full_raw_url)
                        for m in methods:
                            discovered.append(
                                RawExpressRoute(
                                    raw_url=full_raw_url,
                                    normalized_url=norm_url,
                                    method=m,
                                    handler=handler_sym,
                                    middlewares=middlewares,
                                    resolved=resolved,
                                    unresolved_reason=(
                                        None
                                        if resolved
                                        else "router mount prefix is dynamic or unresolved"
                                    ),
                                )
                            )

        return discovered
