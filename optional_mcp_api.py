"""Browser bridge for operator-configured, explicitly allowlisted MCP servers."""
from flask import Blueprint, jsonify, request
from optional_mcp import OptionalMCPRegistry


def create_optional_mcp_blueprint(project_dir, store):
    registry = OptionalMCPRegistry(project_dir)
    bp = Blueprint("optional_mcp", __name__)

    @bp.get("/api/mcp/optional")
    def inventory():
        try:
            return jsonify(registry.snapshot())
        except ValueError as error:
            return jsonify(error=str(error)), 400
        except Exception:
            return jsonify(error="Cannot read MCP configuration. Check the server configuration."), 503

    @bp.post("/api/mcp/optional/<server_id>/probe")
    def probe(server_id):
        try:
            return jsonify(registry.probe(server_id))
        except ValueError as error:
            return jsonify(error=str(error)), 400
        except Exception:
            return jsonify(error="MCP connection failed. Check the configured service."), 503

    @bp.post("/api/mcp/optional/<server_id>/call")
    def invoke(server_id):
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error="A JSON object is required"), 400
        if data.get("authorization_confirmed") is not True:
            return jsonify(error="Explicit operator confirmation is required"), 403
        try:
            result = registry.call(server_id, data.get("tool"), data.get("arguments", {}),
                                   authorization_confirmed=True)
            try:
                result["evidence_id"] = store.record(
                    f"mcp:{server_id}", "mcp", "completed" if result.get("success") else "failed", True, result)
            except Exception:
                result["evidence_error"] = "Tool returned, but local evidence could not be saved. Export this result."
            return jsonify(result)
        except PermissionError:
            return jsonify(error="This tool is not allowlisted in the server configuration"), 403
        except ValueError as error:
            return jsonify(error=str(error)), 400
        except Exception:
            return jsonify(error="MCP tool call failed. Check the configured service."), 503

    return bp
