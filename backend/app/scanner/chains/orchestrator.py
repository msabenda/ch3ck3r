"""Chain orchestrator — runs multiple scanners in sequence with data passing.

The idea: results from one scanner feed into the next for deeper analysis.
- OpenAPI scanner finds API endpoints → feeds them to ZAP for active scanning
- ZAP findings with CWE entries → feed to Nuclei for targeted template runs
- All findings → aggregate into a unified report
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

from app.scanner.engine import BaseScanner, ScanResult, FindingResult
from app.scanner.plugins import get_scanner, get_available_scanners

logger = logging.getLogger(__name__)


@dataclass
class ChainStep:
    """A single step in a scan chain."""
    scanner_name: str
    input_from: Optional[str] = None  # scanner name to pull targets from
    filter_severity: Optional[str] = None  # only pass findings above this severity
    config: dict = field(default_factory=dict)


@dataclass
class ChainConfig:
    """Configuration for a scan chain."""
    name: str
    description: str
    steps: list[ChainStep]


# Pre-defined chains
SCAN_CHAINS = {
    "full_assessment": ChainConfig(
        name="Full API Assessment",
        description="OpenAPI → ZAP → Nuclei: discover endpoints, actively scan, then deep-dive with templates",
        steps=[
            ChainStep(scanner_name="openapi", config={"depth": "full"}),
            ChainStep(scanner_name="zap", input_from="openapi", config={"active_scan": True}),
            ChainStep(scanner_name="nuclei", input_from="zap", filter_severity="medium",
                      config={"template_tags": ["api", "cve"]}),
        ],
    ),
    "quick_check": ChainConfig(
        name="Quick Security Check",
        description="OpenAPI spec analysis + CVE template check",
        steps=[
            ChainStep(scanner_name="openapi", config={"depth": "quick"}),
            ChainStep(scanner_name="nuclei", config={"template_tags": ["cve", "critical"]}),
        ],
    ),
    "deep_dive": ChainConfig(
        name="Deep Dive",
        description="ZAP active scan + Semgrep SAST on source code",
        steps=[
            ChainStep(scanner_name="zap", config={"active_scan": True}),
            ChainStep(scanner_name="semgrep"),
        ],
    ),
    "sast_pipeline": ChainConfig(
        name="SAST Pipeline",
        description="Semgrep full analysis + targeted Nuclei CVE check",
        steps=[
            ChainStep(scanner_name="semgrep", config={"rules": ["p/owasp-top-ten", "p/security-audit"]}),
            ChainStep(scanner_name="nuclei", input_from="semgrep",
                      filter_severity="high",
                      config={"template_tags": ["cve", "api"]}),
        ],
    ),
}


class ChainOrchestrator:
    """Runs a chain of scanners, passing data between steps."""

    def __init__(self):
        self._intermediate_data: dict[str, list] = {}  # scanner_name -> extracted targets

    async def run_chain(
        self, chain_name: str, target: str, repo_url: Optional[str] = None
    ) -> dict[str, ScanResult]:
        """Execute a scan chain and return per-scanner results."""
        chain = SCAN_CHAINS.get(chain_name)
        if not chain:
            raise ValueError(f"Unknown chain: {chain_name}. Available: {list(SCAN_CHAINS.keys())}")

        logger.info(f"Starting chain '{chain_name}' against {target}")
        chain_results: dict[str, ScanResult] = {}

        for step_idx, step in enumerate(chain.steps):
            logger.info(f"Chain step {step_idx + 1}/{len(chain.steps)}: {step.scanner_name}")

            scanner = get_scanner(step.scanner_name)
            if not scanner:
                logger.warning(f"Scanner '{step.scanner_name}' not available, skipping step")
                continue

            # Determine targets for this step
            step_target = target
            if step.input_from and step.input_from in self._intermediate_data:
                extracted = self._intermediate_data[step.input_from]
                if extracted:
                    # Use extracted endpoints as primary targets
                    step_target = extracted[0]  # Primary URL
                    step.config["additional_targets"] = extracted[1:] if len(extracted) > 1 else []
                    step.config["extracted_endpoints"] = extracted

            # Validate
            valid = await scanner.validate_target(step_target)
            if not valid and step.scanner_name == "semgrep":
                step_target = repo_url or step_target
                valid = await scanner.validate_target(step_target)
            if not valid:
                logger.warning(f"Target '{step_target}' invalid for {step.scanner_name}, skipping")
                continue

            # Run the scan
            try:
                result = await scanner.scan(step_target, **step.config)
                chain_results[step.scanner_name] = result

                # Extract targets for next step
                extracted_targets = self._extract_targets(result, step.scanner_name)
                if extracted_targets:
                    self._intermediate_data[step.scanner_name] = extracted_targets

                # Filter findings for next step if configured
                if step.filter_severity and result.findings:
                    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                    min_level = severity_order.get(step.filter_severity, 0)
                    filtered_findings = [
                        f for f in result.findings
                        if severity_order.get(f.severity, 0) >= min_level
                    ]
                    self._intermediate_data[f"{step.scanner_name}_findings"] = filtered_findings

            except Exception as e:
                logger.error(f"Chain step {step.scanner_name} failed: {e}")
                chain_results[step.scanner_name] = ScanResult(
                    plugin_name=step.scanner_name,
                    target=step_target,
                    status="failed",
                    error_message=str(e),
                )

        return chain_results

    def _extract_targets(self, result: ScanResult, scanner_name: str) -> list[str]:
        """Extract API endpoints from scan results for downstream scanners."""
        targets = []
        for f in result.findings:
            if f.endpoint and f.endpoint.startswith(("http://", "https://")):
                # Normalize: remove query params, deduplicate base URLs
                base = f.endpoint.split("?")[0]
                # Get base URL (scheme + host + port)
                parts = base.split("/")
                if len(parts) >= 3:
                    base_url = f"{parts[0]}//{parts[2]}"
                    if base_url not in targets:
                        targets.append(base_url)
        return targets[:10]  # Limit to 10 unique targets per scanner output

    def get_available_chains(self) -> list[dict]:
        """List available scan chains."""
        return [
            {
                "name": c.name,
                "key": key,
                "description": c.description,
                "steps": [s.scanner_name for s in c.steps],
                "step_count": len(c.steps),
            }
            for key, c in SCAN_CHAINS.items()
        ]


# Global chain orchestrator
chain_orchestrator = ChainOrchestrator()
