"""Lacuna agent loop — LLM-driven decision engine.

The agent receives structured observations from the scanner modules
and returns decisions: what to scan next, which candidates to promote,
when to suggest new software to acquire.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path

from anthropic import Anthropic

from lacuna.models import (
    AcquisitionTarget,
    CandidateStatus,
    HijackCandidate,
    HijackType,
    ScanResult,
)

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Lacuna, an expert DLL hijack discovery agent operating within an
authorized purple team engagement. Your job is to find NOVEL DLL hijack
opportunities in Windows software — specifically ones NOT already on
hijacklibs.net or in public CVE databases.

You operate in a loop:
1. Receive observations (scan results, candidate lists, test outcomes)
2. Make decisions (what to scan next, which candidates to promote, what to acquire)
3. Return structured actions

Your priorities:
- NOVELTY: Skip known/burned hijacks. The operator needs something fresh.
- SYSTEM CONTEXT: Prefer targets that run as SYSTEM or are triggered by privileged ops.
- STEALTH: Prefer signed host binaries (makes the hijack blend in).
- FEASIBILITY: Prefer targets with few exports (easier proxy) and writable paths.
- STABILITY: Flag candidates where the host app might crash without full export forwarding.

When suggesting software to acquire:
- Think like an enterprise IT environment — what's widely deployed but under-researched?
- Consider the target org's likely stack if context is provided.
- Prefer software with background services, updaters, or scheduled tasks.
- Avoid consumer-only apps unless they have SYSTEM components.

Output JSON actions. Available action types:
- scan_directory: {path, recursive}
- scan_binary: {path}
- run_dynamic: {target_exe, duration_seconds}
- promote_candidate: {dll_name, target_exe, reason}
- reject_candidate: {dll_name, target_exe, reason}
- deploy_canary: {dll_name, target_exe, plant_path}
- generate_proxy: {dll_name, dll_path}
- suggest_acquisition: {targets: [{name, category, rationale, install_method}]}
- ask_operator: {question, context}
- report: {findings: [...], recommendations: [...]}
"""


class ActionType(Enum):
    SCAN_DIRECTORY = "scan_directory"
    SCAN_BINARY = "scan_binary"
    RUN_DYNAMIC = "run_dynamic"
    PROMOTE = "promote_candidate"
    REJECT = "reject_candidate"
    DEPLOY_CANARY = "deploy_canary"
    GENERATE_PROXY = "generate_proxy"
    SUGGEST_ACQUISITION = "suggest_acquisition"
    ASK_OPERATOR = "ask_operator"
    REPORT = "report"


@dataclass
class AgentAction:
    action_type: ActionType
    params: dict = field(default_factory=dict)
    reasoning: str = ""


@dataclass
class AgentState:
    """Accumulated state the agent reasons over."""

    targets_scanned: list[str] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    confirmed_hits: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    installed_software: list[str] = field(default_factory=list)
    operator_context: str = ""
    iteration: int = 0


class LacunaAgent:
    def __init__(self, api_key: str | None = None, model: str = "claude-sonnet-4-20250514"):
        self.client = Anthropic(api_key=api_key)
        self.model = model
        self.state = AgentState()
        self.conversation: list[dict] = []

    def reset(self):
        self.state = AgentState()
        self.conversation = []

    def set_operator_context(self, context: str):
        """Provide context about the target org/environment."""
        self.state.operator_context = context

    def decide(self, observation: dict) -> list[AgentAction]:
        """Send observation to LLM, get back actions.

        Args:
            observation: Structured data about what just happened
                (scan results, canary outcomes, etc.)

        Returns:
            List of actions to execute
        """
        self.state.iteration += 1

        # Build the message
        user_msg = self._format_observation(observation)
        self.conversation.append({"role": "user", "content": user_msg})

        response = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=self.conversation,
        )

        assistant_text = response.content[0].text
        self.conversation.append({"role": "assistant", "content": assistant_text})

        actions = self._parse_actions(assistant_text)
        return actions

    def _format_observation(self, observation: dict) -> str:
        """Format observation + current state for the LLM."""
        state_summary = {
            "iteration": self.state.iteration,
            "targets_scanned": len(self.state.targets_scanned),
            "active_candidates": len(self.state.candidates),
            "confirmed_hits": len(self.state.confirmed_hits),
            "rejected": len(self.state.rejected),
            "installed_software": self.state.installed_software,
        }

        if self.state.operator_context:
            state_summary["operator_context"] = self.state.operator_context

        msg = (
            f"## Current State\n```json\n{json.dumps(state_summary, indent=2)}\n```\n\n"
            f"## Observation\n```json\n{json.dumps(observation, indent=2, default=str)}\n```\n\n"
            "Respond with a JSON array of actions to take next. "
            "Include a 'reasoning' field explaining your logic."
        )
        return msg

    def _parse_actions(self, response_text: str) -> list[AgentAction]:
        """Parse LLM response into structured actions."""
        # Extract JSON from response (may be wrapped in markdown)
        json_str = response_text
        if "```json" in response_text:
            start = response_text.index("```json") + 7
            end = response_text.index("```", start)
            json_str = response_text[start:end]
        elif "```" in response_text:
            start = response_text.index("```") + 3
            end = response_text.index("```", start)
            json_str = response_text[start:end]

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            log.error("Failed to parse agent response as JSON")
            log.debug("Raw response: %s", response_text)
            return [AgentAction(
                action_type=ActionType.ASK_OPERATOR,
                params={"question": "Agent produced unparseable output. Manual review needed.",
                        "raw_response": response_text[:500]},
            )]

        if isinstance(data, dict):
            # Single action or wrapped in a key
            if "actions" in data:
                data = data["actions"]
            else:
                data = [data]

        actions = []
        for item in data:
            try:
                action_type = ActionType(item.get("action_type", item.get("type", "")))
                actions.append(AgentAction(
                    action_type=action_type,
                    params={k: v for k, v in item.items() if k not in ("action_type", "type", "reasoning")},
                    reasoning=item.get("reasoning", ""),
                ))
            except (ValueError, KeyError) as e:
                log.warning("Skipping unparseable action: %s (%s)", item, e)

        return actions

    def update_state(self, action: AgentAction, result: dict):
        """Update agent state after an action is executed."""
        if action.action_type == ActionType.SCAN_DIRECTORY:
            self.state.targets_scanned.append(action.params.get("path", ""))
        elif action.action_type == ActionType.PROMOTE:
            self.state.candidates.append(action.params)
        elif action.action_type == ActionType.REJECT:
            self.state.rejected.append(action.params)
        elif action.action_type == ActionType.DEPLOY_CANARY:
            if result.get("success"):
                self.state.confirmed_hits.append({**action.params, **result})

    def get_initial_actions(self) -> list[AgentAction]:
        """Generate first-round actions based on available context."""
        observation = {
            "type": "session_start",
            "message": (
                "New Lacuna session. No targets scanned yet. "
                "Determine initial scan strategy based on available context."
            ),
            "available_modules": [
                "static_analyzer (cross-platform PE import analysis)",
                "dynamic_monitor (procmon/ETW capture — Windows only)",
                "canary (compile + deploy test DLLs)",
                "proxy_generator (full proxy DLL source generation)",
                "target_acquisition (suggest/install new software)",
                "windows_enumeration (services, tasks, auto-runs, ACLs)",
                "hijacklibs (novelty check against known database)",
            ],
        }
        return self.decide(observation)
