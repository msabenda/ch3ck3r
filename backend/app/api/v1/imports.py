"""Import API specifications for scanning.

Supports OpenAPI/Swagger JSON/YAML, Postman collections, HAR files,
API Blueprint, and RAML formats.
"""
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from app.core.security import get_current_user
import json, yaml

router = APIRouter()


def _extract_postman(items, base_url=""):
    """Recursively extract endpoints from Postman collection items."""
    result = []
    for item in items:
        if "item" in item:
            result.extend(_extract_postman(item["item"], base_url))
        elif "request" in item:
            req = item["request"]
            url_obj = req.get("url", {})
            if isinstance(url_obj, dict):
                url = url_obj.get("raw", "")
            else:
                url = str(url_obj)
            result.append({
                "method": req.get("method", "GET"),
                "path": url,
                "url": url,
                "summary": item.get("name", ""),
                "headers": req.get("header", []),
            })
    return result


@router.post("/detect")
async def detect_format(
    file: UploadFile = File(...),
    current_user=Depends(get_current_user),
):
    """Auto-detect the API specification format from an uploaded file."""
    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    filename = (file.filename or "").lower()

    result = {
        "filename": file.filename,
        "size_bytes": len(content),
        "format": None,
        "endpoints": [],
        "spec_info": {},
    }

    # Try JSON parsing first
    try:
        data = json.loads(text)
        if "openapi" in data:
            result["format"] = "openapi-3.x"
            info = data.get("info", {})
            paths = data.get("paths", {})
            result["spec_info"] = {
                "version": data.get("openapi", "3.0.0"),
                "title": info.get("title", ""),
                "api_version": info.get("version", ""),
                "endpoint_count": len(paths),
                "security": data.get("security", []),
            }
            for path, methods in paths.items():
                if isinstance(methods, dict):
                    for method in methods:
                        if isinstance(methods[method], dict):
                            result["endpoints"].append(
                                f"{method.upper()} {path}"
                            )
        elif "swagger" in data:
            result["format"] = "swagger-2.x"
            paths = data.get("paths", {})
            result["spec_info"] = {
                "version": data.get("swagger", "2.0"),
                "title": data.get("info", {}).get("title", ""),
                "endpoint_count": len(paths),
            }
            for path, methods in paths.items():
                if isinstance(methods, dict):
                    for method in methods:
                        if isinstance(methods[method], dict):
                            result["endpoints"].append(
                                f"{method.upper()} {path}"
                            )
        elif "info" in data and "item" in data:
            result["format"] = "postman-collection-v2"
            items = data.get("item", [])
            result["spec_info"] = {
                "name": data.get("info", {}).get("name", ""),
                "item_count": len(items),
            }
        elif "log" in data and "entries" in data.get("log", {}):
            result["format"] = "har"
            entries = data["log"]["entries"]
            result["spec_info"] = {
                "entry_count": len(entries),
                "started": entries[0].get("startedDateTime", "")
                if entries else "",
            }
            for entry in entries:
                req = entry.get("request", {})
                result["endpoints"].append(
                    f"{req.get('method', 'GET')} {req.get('url', '')}"
                )
    except json.JSONDecodeError:
        # Try YAML
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict):
                if "openapi" in data:
                    result["format"] = "openapi-3.x-yaml"
                    paths = data.get("paths", {})
                    result["spec_info"] = {
                        "title": data.get("info", {}).get("title", ""),
                        "endpoint_count": len(paths),
                    }
                    for path, methods in paths.items():
                        if isinstance(methods, dict):
                            for method in methods:
                                if isinstance(methods[method], dict):
                                    result["endpoints"].append(
                                        f"{method.upper()} {path}"
                                    )
                elif "swagger" in data:
                    result["format"] = "swagger-2.x-yaml"
                elif "info" in data and "item" in data:
                    result["format"] = "postman-collection-json"
                else:
                    result["format"] = "yaml-generic"
        except Exception:
            # Raw text formats
            if text.startswith("# ") or "FORMAT:" in text or "HOST:" in text:
                result["format"] = "api-blueprint"
            elif "#%RAML" in text or (
                "title:" in text and "version:" in text and "baseUri:" in text
            ):
                result["format"] = "raml"
            else:
                result["format"] = "unknown"

    return result


@router.post("/parse")
async def parse_specification(
    file: UploadFile = File(...),
    project_id: str = Form(None),
    current_user=Depends(get_current_user),
):
    """Parse an API specification and extract endpoints for scanning."""
    content = await file.read()
    text = content.decode("utf-8", errors="replace")

    # Detect and parse
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            data = yaml.safe_load(text)
        except Exception as exc:
            raise HTTPException(
                400, f"Could not parse specification: {exc}"
            )

    if not isinstance(data, dict):
        raise HTTPException(400, "Invalid specification format")

    endpoints = []

    if "openapi" in data or "swagger" in data:
        base_url = ""
        if "servers" in data and data["servers"]:
            base_url = data["servers"][0].get("url", "")
        elif "host" in data:
            scheme = (data.get("schemes") or ["https"])[0]
            base_url = (
                f"{scheme}://{data['host']}{data.get('basePath', '')}"
            )

        for path, methods in data.get("paths", {}).items():
            if isinstance(methods, dict):
                for method in methods:
                    if isinstance(methods[method], dict):
                        full_url = (
                            f"{base_url}{path}" if base_url else path
                        )
                        endpoints.append({
                            "method": method.upper(),
                            "path": path,
                            "url": full_url,
                            "summary": methods[method].get("summary", ""),
                            "parameters": methods[method].get(
                                "parameters", []
                            ),
                            "security": methods[method].get(
                                "security", data.get("security", [])
                            ),
                        })

    elif "item" in data:
        # Postman collection
        endpoints = _extract_postman(data.get("item", []))

    elif "log" in data:
        # HAR file
        for entry in data.get("log", {}).get("entries", []):
            req = entry.get("request", {})
            endpoints.append({
                "method": req.get("method", "GET"),
                "path": req.get("url", ""),
                "url": req.get("url", ""),
                "headers": req.get("headers", []),
                "response_status": entry.get("response", {}).get("status"),
            })

    source = file.filename or "imported"
    base_url_spec = ""
    if endpoints:
        # Try to extract base URL from first endpoint
        first = endpoints[0].get("url", "")
        if first.startswith("http"):
            from urllib.parse import urlparse
            parsed = urlparse(first)
            base_url_spec = f"{parsed.scheme}://{parsed.netloc}"

    return {
        "status": "parsed",
        "source": source,
        "endpoint_count": len(endpoints),
        "base_url": base_url_spec,
        "endpoints": endpoints,
    }
