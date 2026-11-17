"""A2A (Agent2Agent, v1.0) front end for the same PacketFabric operations the MCP tools expose.

This is a deterministic "skill" agent, not an LLM: the caller picks a skill and passes
arguments as structured data, and gets the API result back as a data artifact.

Request message (one DataPart):
    {"skill": "list_ports", "arguments": {"pop": "LAX1"}}
or a TextPart holding the same JSON, or just a skill id ("get_account").
Anything else gets a help message listing the skills.

Auth: the caller's own PacketFabric API key, as `Authorization: Bearer <key>` on the A2A
HTTP request. Writes are never available over A2A (call_endpoint is read-only here).

Requires the optional dependency group: `pip install 'packetfabric-mcp[a2a]'`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from a2a.helpers import get_data_parts, get_text_parts, new_data_part, new_task, new_text_message, new_text_part
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentProvider,
    AgentSkill,
    HTTPAuthSecurityScheme,
    SecurityRequirement,
    SecurityScheme,
    StringList,
    TaskState,
)
from mcp.server.mcpserver.exceptions import ToolError

from . import metadata, server
from .client import caller_credentials, credentials_from_headers
from .oauth.seal import clean_bearer, is_sign_in_artifact

A2A_PROTOCOL_VERSION = "1.0"
SECURITY_SCHEME_ID = "packetfabricApiKey"


@dataclass(frozen=True)
class Skill:
    id: str
    name: str
    description: str
    tags: tuple[str, ...]
    tool: str  # the MCP tool this skill runs (arguments are validated by its schema)
    examples: tuple[str, ...] = ()


def _example(skill: str, **arguments: Any) -> str:
    return json.dumps({"skill": skill, "arguments": arguments} if arguments else {"skill": skill})



SKILLS: tuple[Skill, ...] = (
    Skill("get_account", "Get account", "The caller's PacketFabric customer account (name, account number, UUID).",
          ("account",), "pf_get_account", (_example("get_account"),)),
    Skill("list_ports", "List ports", "Access ports, LAGs and cloud ports with speed, status and POP. "
          "Arguments: q, pop, market, is_lag, is_cloud, is_ptp, fields, max_items.",
          ("ports", "inventory"), "pf_list_ports", (_example("list_ports", pop="LAX1"),)),
    Skill("get_port", "Get port", "Full details for one port. Arguments: port_circuit_id.",
          ("ports",), "pf_get_port", (_example("get_port", port_circuit_id="PF-AP-LAX1-1234"),)),
    Skill("list_services", "List virtual circuits", "Virtual circuits: backbone, cloud, IX, marketplace. "
          "Arguments: q, port_circuit_id, service_type (list), fields, max_items.",
          ("virtual-circuits", "inventory"), "pf_list_services",
          (_example("list_services", service_type=["backbone"]),)),
    Skill("list_point_to_point", "List point-to-point services", "Point-to-point services. Arguments: q.",
          ("ptp", "inventory"), "pf_list_point_to_point"),
    Skill("list_cloud_routers", "List Cloud Routers", "Layer-3 Cloud Routers on the account.",
          ("cloud-router", "inventory"), "pf_list_cloud_routers"),
    Skill("list_cloud_router_connections", "List Cloud Router connections",
          "Connections on all Cloud Routers, or one. Arguments: cloud_router_circuit_id.",
          ("cloud-router", "inventory"), "pf_list_cloud_router_connections"),
    Skill("list_cloud_connections", "List cloud connections",
          "Layer-2 hosted or dedicated connections to AWS/Azure/Google/Oracle/IBM. Arguments: kind (hosted|dedicated), q.",
          ("cloud", "inventory"), "pf_list_cloud_connections"),
    Skill("find_locations", "Find locations", "PacketFabric POPs and data centers. "
          "Arguments: pop, city, state, market, region, any_type, near_cloud_router, ipsec_capable, nat_capable.",
          ("locations",), "pf_find_locations", (_example("find_locations", market="NYC"),)),
    Skill("get_pricing", "Get pricing", "List pricing (MRC/NRC) for a product between locations; never orders anything. "
          "Arguments: product_type (required), location_type, side_a, side_z, speed, subscription_term, service_class, media.",
          ("pricing", "quote"), "pf_get_pricing",
          (_example("get_pricing", product_type="vcbwc", side_a="LAX1", side_z="NYC5", speed="10Gbps"),)),
    Skill("get_traffic", "Get traffic", "bps/pps time series for a port or one VC on a port. "
          "Arguments: port_circuit_id (required), vc_circuit_id, type, since, until, interval.",
          ("metrics", "traffic"), "pf_get_traffic",
          (_example("get_traffic", port_circuit_id="PF-AP-LAX1-1234", since="7 days ago", interval=3600),)),
    Skill("get_maintenances", "Get maintenances", "Current and upcoming maintenance windows. Arguments: pop, market.",
          ("maintenance",), "pf_get_maintenances"),
    Skill("search_endpoints", "Search API endpoints", "Keyword search over every PacketFabric API operation. "
          "Arguments: query, tag, read_only, limit.", ("api", "discovery"), "pf_search_endpoints"),
    Skill("describe_endpoint", "Describe API endpoint", "Parameters and schemas for one operation. Arguments: operation_id.",
          ("api", "discovery"), "pf_describe_endpoint"),
    Skill("call_endpoint", "Call API endpoint (read-only)", "Call any read-only PacketFabric API operation by id. "
          "Arguments: operation_id, params, fields, max_items.", ("api",), "pf_call_endpoint",
          (_example("call_endpoint", operation_id="get_location_market_list"),)),
)
SKILLS_BY_ID = {s.id: s for s in SKILLS}


def build_agent_card(base_url: str) -> AgentCard:
    base = base_url.rstrip("/")
    card = AgentCard(
        name=f"{metadata.TITLE} Network Agent",
        description=metadata.LONG_DESCRIPTION
        + " Send a DataPart {\"skill\": <id>, \"arguments\": {...}}; results come back as a JSON data artifact.",
        version=metadata.VERSION,
        provider=AgentProvider(organization=metadata.ORGANIZATION, url=metadata.ORGANIZATION_URL),
        documentation_url=metadata.REPOSITORY_URL,
        supported_interfaces=[
            AgentInterface(url=base + metadata.A2A_PATH, protocol_binding="JSONRPC", protocol_version=A2A_PROTOCOL_VERSION)
        ],
        capabilities=AgentCapabilities(streaming=False, push_notifications=False),
        security_schemes={
            SECURITY_SCHEME_ID: SecurityScheme(
                http_auth_security_scheme=HTTPAuthSecurityScheme(
                    scheme="Bearer", description="Your PacketFabric API key (portal: Settings > API Keys)."
                )
            )
        },
        security_requirements=[SecurityRequirement(schemes={SECURITY_SCHEME_ID: StringList(list=[])})],
        default_input_modes=["application/json", "text/plain"],
        default_output_modes=["application/json"],
        skills=[
            AgentSkill(id=s.id, name=s.name, description=s.description, tags=list(s.tags), examples=list(s.examples))
            for s in SKILLS
        ],
    )
    if metadata.ICON_URL:
        card.icon_url = metadata.ICON_URL
    return card


def _help_text(problem: str | None = None) -> str:
    lines = [problem] if problem else []
    lines.append('Send a DataPart like {"skill": "list_ports", "arguments": {"pop": "LAX1"}}. Skills:')
    lines += [f"- {s.id}: {s.description}" for s in SKILLS]
    return "\n".join(lines)


def parse_request(message: Any) -> tuple[Skill | None, dict[str, Any], str | None]:
    """Return (skill, arguments, error)."""
    payload: Any = None
    for data in get_data_parts(message.parts):
        if isinstance(data, dict) and "skill" in data:
            payload = data
            break
    if payload is None:
        text = "\n".join(get_text_parts(message.parts)).strip()
        if not text:
            return None, {}, "Empty request."
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = {"skill": text.split()[0]} if len(text.split()) == 1 else None
        if not isinstance(payload, dict):
            return None, {}, "Free-text requests aren't supported; pick a skill."
    skill = SKILLS_BY_ID.get(str(payload.get("skill", "")))
    if skill is None:
        return None, {}, f"Unknown skill {payload.get('skill')!r}."
    args = payload.get("arguments") or {}
    if not isinstance(args, dict):
        return None, {}, "'arguments' must be an object."
    return skill, args, None


class PacketFabricAgentExecutor(AgentExecutor):
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        message = context.message
        skill, args, error = parse_request(message) if message else (None, {}, "Empty request.")
        if skill is None:
            await event_queue.enqueue_event(new_text_message(_help_text(error), context_id=context.context_id))
            return

        # No credentials: answer with a plain message so no task (and no owner) is ever created.
        headers = (context.call_context.state or {}).get("headers") if context.call_context else None
        creds = credentials_from_headers(headers)
        key = clean_bearer(creds.token) if creds is not None and creds.token else None
        if key is None:
            await event_queue.enqueue_event(new_text_message(metadata.AUTH_HELP, context_id=context.context_id))
            return
        # A2A has no sign-in: our own tokens are never forwarded to PacketFabric as keys.
        if is_sign_in_artifact(key):
            await event_queue.enqueue_event(
                new_text_message(metadata.A2A_SIGN_IN_TOKEN_HELP, context_id=context.context_id)
            )
            return

        task = context.current_task or new_task(
            context.task_id, context.context_id, TaskState.TASK_STATE_SUBMITTED, history=[message]
        )
        if context.current_task is None:
            await event_queue.enqueue_event(task)
        updater = TaskUpdater(event_queue, task.id, task.context_id)
        await updater.start_work()

        if skill.id == "call_endpoint":
            op = server.spec().get(str(args.get("operation_id", "")))
            if op is not None and not op.is_read_only:
                await updater.reject(
                    updater.new_agent_message([new_text_part("call_endpoint over A2A is read-only.")])
                )
                return
            args = {k: v for k, v in args.items() if k != "confirm"}

        token = caller_credentials.set(creds)
        try:
            outcome = await server.mcp.call_tool(skill.tool, args)
            result = outcome.content[0].text if outcome.content else ""
            if getattr(outcome, "is_error", False):
                raise ToolError(result)
        except Exception as e:  # validation errors, API errors, missing credentials
            msg = str(e).removeprefix(f"Error executing tool {skill.tool}: ")
            await updater.failed(updater.new_agent_message([new_text_part(msg)]))
            return
        finally:
            caller_credentials.reset(token)

        try:
            part = new_data_part(json.loads(result), media_type="application/json")
        except (json.JSONDecodeError, TypeError, ValueError):
            part = new_text_part(str(result))
        await updater.add_artifact([part], name=skill.id)
        await updater.complete()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        # Every skill is a single short API call; nothing to interrupt.
        if context.task_id and context.context_id:
            await TaskUpdater(event_queue, context.task_id, context.context_id).cancel()
