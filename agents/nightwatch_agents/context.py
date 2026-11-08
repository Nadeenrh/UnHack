"""Bounded context and deterministic provenance, independent of model text."""

import ipaddress
import json
import re

from .contracts import FORMAT_CHECKER

MAX_EVENTS = 20
MAX_FIELDS = 32
MAX_TEXT = 400
MAX_CONTEXT_BYTES = 10000
INJECTION = re.compile(
    r"ignore[\s_-]+(?:all[\s_-]+)?(?:previous|prior|above)[\s_-]+instructions|"
    r"(?:system|developer)[\s_-]+(?:prompt|message)|"
    r"mark[\s_-]+(?:this[\s_-]+)?benign|<\|(?:im_start|system)\|>", re.I
)


def scalar_fields(value, path="", depth=0, omitted=None):
    if omitted is None:
        omitted = [False]
    if depth > 8:
        omitted[0] = True
        return
    if isinstance(value, dict):
        if len(value) > 64:
            omitted[0] = True
        for key, child in list(value.items())[:64]:
            escaped = key.replace("~", "~0").replace("/", "~1")
            yield from scalar_fields(child, path + "/" + escaped, depth + 1, omitted)
    elif isinstance(value, list):
        if len(value) > 32:
            omitted[0] = True
        for i, child in enumerate(value[:32]):
            yield from scalar_fields(child, path + "/" + str(i), depth + 1, omitted)
    elif isinstance(value, (str, int, float, bool)):
        yield path, value


def normalize_ip(value):
    try:
        return str(ipaddress.ip_address(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def public_ip(value):
    address = ipaddress.ip_address(value)
    # Python versions differ on some special networks; explicitly exclude mapped
    # IPv4 and transition addresses as well as non-global/multicast addresses.
    return (address.is_global and not address.is_multicast
            and not getattr(address, "ipv4_mapped", None)
            and not getattr(address, "sixtofour", None)
            and not getattr(address, "teredo", None))


def build_context(request):
    events = [request["alert"], *request["related_events"]]
    records, indicators, own_ips, hosts = [], [], set(), set()
    used, truncated = 0, len(events) > MAX_EVENTS
    # Detection inspects the bounded HTTP payload, even fields omitted from LLM input.
    injection = bool(INJECTION.search(json.dumps(request, ensure_ascii=True)))
    for index, event in enumerate(events):
        agent = event.get("agent")
        if isinstance(agent, dict):
            own = normalize_ip(agent.get("ip"))
            if own:
                own_ips.add(own)
            if isinstance(agent.get("name"), str):
                hosts.add(agent["name"])
        if index >= MAX_EVENTS:
            continue
        root = "/alert" if index == 0 else "/related_events/" + str(index - 1)
        fields = []
        timestamp = event.get("timestamp")
        if isinstance(timestamp, str):
            # Wazuh uses +0000; JSON Schema requires +00:00.
            timestamp = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", timestamp)
        if not isinstance(timestamp, str) or not FORMAT_CHECKER.conforms(timestamp, "date-time"):
            timestamp = None
        omitted = [False]
        for path, value in scalar_fields(event, omitted=omitted):
            if path in ("/data/srcip", "/data/win/eventdata/ipAddress"):
                ip = normalize_ip(value)
                if ip and ("ip", ip) not in indicators:
                    indicators.append(("ip", ip))
            if path.endswith("/sha256") and isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value):
                item = ("sha256", value.lower())
                if item not in indicators:
                    indicators.append(item)
            if path in ("/data/domain", "/data/query") and isinstance(value, str):
                domain = value.lower().rstrip(".")
                if re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
                    if ("domain", domain) not in indicators:
                        indicators.append(("domain", domain))
            text = value if isinstance(value, str) else json.dumps(value)
            if len(fields) >= MAX_FIELDS or len(text) > MAX_TEXT or len(path) > 200:
                truncated = True
                continue  # Never present a partial field as complete evidence.
            field = {"ref": root + path, "text": text, "observed_at": timestamp}
            size = len(json.dumps(field, ensure_ascii=True).encode())
            if used + size > MAX_CONTEXT_BYTES:
                truncated = True
                continue
            used += size
            fields.append(field)
        records.extend(fields)
        truncated = truncated or omitted[0]
    return {"records": records, "truncated": truncated,
            "injection_detected": injection, "indicators": indicators[:12],
            "own_ips": own_ips, "hosts": hosts}


def evidence_from_quotes(quotes, context):
    records = {field["ref"]: field for field in context["records"]}
    evidence = []
    for item in quotes:
        field = records.get(item["ref"])
        if (field is None or not field["observed_at"] or not item["quote"].strip()
                or item["quote"] not in field["text"]):
            raise ValueError("Evidence reference or exact quotation is invalid")
        evidence.append({"claim": "Observed log text: " + item["quote"], "source": "wazuh",
                         "log_ref": item["ref"], "observed_at": field["observed_at"]})
    return evidence
