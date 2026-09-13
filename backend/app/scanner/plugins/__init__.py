"""Scanner plugin registry — discover and run plugins.

Imports and registers all built-in scanner plugins.
"""

from typing import Optional
from app.scanner.engine import BaseScanner, ScanResult


_PLUGIN_REGISTRY: dict[str, type[BaseScanner]] = {}
_INSTANCE_CACHE: dict[str, BaseScanner] = {}


def register_scanner(scanner_cls: type[BaseScanner]):
    """Register a scanner plugin class."""
    instance = scanner_cls()
    _PLUGIN_REGISTRY[instance.name] = scanner_cls
    _INSTANCE_CACHE[instance.name] = instance
    return scanner_cls


def get_scanner(name: str) -> Optional[BaseScanner]:
    """Get a scanner instance by name."""
    if name in _INSTANCE_CACHE:
        return _INSTANCE_CACHE[name]
    if name in _PLUGIN_REGISTRY:
        inst = _PLUGIN_REGISTRY[name]()
        _INSTANCE_CACHE[name] = inst
        return inst
    return None


def get_available_scanners() -> list[str]:
    """List registered scanner names."""
    return list(_PLUGIN_REGISTRY.keys())


def list_scanners() -> list[BaseScanner]:
    """Get all scanner instances."""
    return [get_scanner(name) for name in get_available_scanners() if get_scanner(name)]


# ─── Import and register all built-in plugins ───────────────────
from app.scanner.plugins.openapi_scanner import OpenAPIScanner
register_scanner(OpenAPIScanner)

try:
    from app.scanner.plugins.zap_scanner import ZAPScanner
    register_scanner(ZAPScanner)
except ImportError:
    pass

try:
    from app.scanner.plugins.nuclei_scanner import NucleiScanner
    register_scanner(NucleiScanner)
except ImportError:
    pass

try:
    from app.scanner.plugins.semgrep_scanner import SemgrepScanner
    register_scanner(SemgrepScanner)
except ImportError:
    pass


# ─── Multi-scanner orchestration ────────────────────────────────

async def run_full_scan(target: str, repo_url: Optional[str] = None) -> dict[str, ScanResult]:
    """Run all available scanners against a target and return results by scanner name."""
    results = {}
    scanners = list_scanners()

    for scanner in scanners:
        valid = await scanner.validate_target(target)
        if not valid and repo_url:
            valid = await scanner.validate_target(repo_url)
        if not valid:
            continue

        scan_target = repo_url if repo_url and scanner.name in ("semgrep",) else target
        result = await scanner.scan(scan_target)
        results[scanner.name] = result

    return results
