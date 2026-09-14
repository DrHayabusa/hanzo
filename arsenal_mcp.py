"""Generate MCP tools for every bundled HexStrike /api/tools POST adapter.

One MCP tool is registered per catalogued route, with argument names, types and
defaults taken from the same read-only catalog that drives the browser launcher.
Generation never imports or executes a scanner.

Doctrine preserved from the GUI:
- Active commands require explicit operator authorization; nothing runs implicitly.
- A missing executable is reported as missing. Readiness is never fabricated.
- Executable presence is not proof of a working command, credentials or wordlists.
"""

import inspect
import re
from typing import Any, Callable, Dict, List, Optional

TYPES = {"str": str, "string": str, "int": int, "integer": int, "float": float,
         "bool": bool, "boolean": bool, "array": list, "list": list,
         "object": dict, "dict": dict}
EMPTY = {str: "", int: 0, float: 0.0, bool: False, list: list, dict: dict}
# Never let a catalogued argument name shadow the transport/authorization contract.
RESERVED = {"authorization_confirmed", "self", "return"}
NAME_PREFIX = "run_"


def tool_name(command_id: str) -> str:
    """Map a catalog command id onto a stable, valid MCP tool name."""
    slug = re.sub(r"[^a-z0-9]+", "_", str(command_id).lower()).strip("_")
    return f"{NAME_PREFIX}{slug or 'command'}"


def _annotation(field: Dict[str, Any]) -> type:
    return TYPES.get(str(field.get("type", "str")).lower(), str)


def _default(field: Dict[str, Any], annotation: type) -> Any:
    default = field.get("default")
    if default is None or not isinstance(default, annotation):
        blank = EMPTY[annotation]
        return blank() if callable(blank) else blank
    return default


def usable_fields(command: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Catalog fields that can be represented as MCP arguments, de-duplicated."""
    seen, fields = set(), []
    for field in command.get("fields") or []:
        name = str(field.get("name") or "")
        if not name.isidentifier() or name in RESERVED or name in seen:
            continue
        seen.add(name)
        fields.append(field)
    return fields


def describe(command: Dict[str, Any], readiness: Optional[bool]) -> str:
    """Build a truthful tool description including the current readiness state."""
    state = {True: "Executable detected on the worker PATH; presence is not a functional test.",
             False: "NOT INSTALLED on the worker. Install it on Kali, then call refresh_arsenal_catalog.",
             None: "Runtime-dependent adapter; readiness cannot be checked by looking for one binary."}[readiness]
    summary = (command.get("description") or "").strip() or f"HexStrike {command.get('id')} adapter"
    return (f"{summary}\n\n"
            f"Category: {command.get('category')} | Route: POST {command.get('endpoint')}\n"
            f"Readiness: {state}\n"
            f"Requires authorization_confirmed=true. Only run against assets you own or are "
            f"explicitly authorized to test. Command completion is not a security verdict.")


def build_arguments(command: Dict[str, Any], supplied: Dict[str, Any]) -> Dict[str, Any]:
    """Mirror the browser launcher: omit blank optional text, keep typed defaults."""
    payload: Dict[str, Any] = {}
    for field in usable_fields(command):
        name = field["name"]
        if name not in supplied:
            continue
        value = supplied[name]
        if isinstance(value, str):
            if not value.strip():
                if field.get("required"):
                    raise ValueError(f"{name} is required for {command.get('id')}")
                continue
            value = value.strip()
        payload[name] = value
    for field in usable_fields(command):
        if field.get("required") and field["name"] not in payload:
            raise ValueError(f"{field['name']} is required for {command.get('id')}")
    payload["authorization_confirmed"] = True
    return payload


def make_tool(command: Dict[str, Any], invoke: Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]],
              readiness: Callable[[str], Optional[bool]]) -> Callable[..., Dict[str, Any]]:
    """Create a typed callable for one catalogued command."""
    command_id = str(command.get("id"))
    fields = usable_fields(command)

    def run(**supplied: Any) -> Dict[str, Any]:
        if supplied.pop("authorization_confirmed", False) is not True:
            raise RuntimeError(
                f"Explicit authorization is required before running {command_id}. "
                f"Confirm you own or are authorized to test the target, then call again "
                f"with authorization_confirmed=true.")
        state = readiness(command_id)
        if state is False:
            raise RuntimeError(
                f"{command.get('tool') or command_id} is not installed on this worker. "
                f"Install it (bash scripts/install_kali_arsenal.sh) and call "
                f"refresh_arsenal_catalog; HANZO does not fake tool readiness.")
        return invoke(command, build_arguments(command, supplied))

    parameters, annotations = [], {}
    for field in fields:
        annotation = _annotation(field)
        annotations[field["name"]] = annotation
        parameters.append(inspect.Parameter(field["name"], inspect.Parameter.KEYWORD_ONLY,
                                            default=_default(field, annotation), annotation=annotation))
    annotations["authorization_confirmed"] = bool
    parameters.append(inspect.Parameter("authorization_confirmed", inspect.Parameter.KEYWORD_ONLY,
                                        default=False, annotation=bool))
    annotations["return"] = dict
    run.__signature__ = inspect.Signature(parameters, return_annotation=dict)
    run.__annotations__ = annotations
    run.__name__ = tool_name(command_id)
    run.__doc__ = describe(command, readiness(command_id))
    return run


def commands_from_catalog(catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten the catalog into an ordered command list."""
    commands = []
    for category in catalog.get("categories") or []:
        for command in category.get("commands") or []:
            if str(command.get("endpoint", "")).startswith("/api/tools/"):
                commands.append(command)
    return commands


def register(mcp, catalog: Dict[str, Any],
             invoke: Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]],
             readiness: Callable[[str], Optional[bool]]) -> List[str]:
    """Register one MCP tool per catalogued command. Returns the registered names."""
    registered, used = [], set()
    for command in commands_from_catalog(catalog):
        name = tool_name(command.get("id"))
        if name in used:
            continue
        used.add(name)
        mcp.add_tool(make_tool(command, invoke, readiness))
        registered.append(name)
    return registered
