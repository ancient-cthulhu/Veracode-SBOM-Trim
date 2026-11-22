#!/usr/bin/env python3
"""Remove first-party components, unmatched files and build paths from Veracode SCA CycloneDX SBOMs.

Input: CycloneDX 1.4-1.6 JSON or XML from the Veracode SBOM REST API
(application/agent), the agent CLI (``srcclr scan --sbom ...``) or the Veracode
CLI (``veracode sbom``, Syft). Output matches the input format unless
``--output-format`` is set. SPDX is rejected.

Filters are opt-in (``--help``). Core is stdlib only; output is schema-validated
when ``cyclonedx-python-lib[json-validation,xml-validation]`` is installed. No
network calls.
"""

from __future__ import annotations

import argparse
import copy
import fnmatch
import json
import os
import re
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

__version__ = "1.4.0"
TOOL_NAME = "sbom_trim"
SUPPORTED_SPECS = ("1.4", "1.5", "1.6")
REDACTED_NAME = "REDACTED"
REDACTED_PROPERTY = "external:redacted"
# Kept on a redacted placeholder; anything else can identify it.
REDACT_KEEP_FIELDS = ("type", "scope", "components")

# Veracode-specific component properties (observed in Veracode SCA exports).
VC_MATCH_TYPE = "Match Type"
VC_UNMATCHED = "Unmatched"
VC_FILE_PATH = "File Path"
VC_SCAN_TYPE = "veracode:scan_type"
# Path props that can name an outer file: Veracode "File Path", Syft location/virtualPath.
SYFT_VIRTUAL_PATH = "syft:metadata:virtualPath"
SYFT_LOCATION_RE = re.compile(r"^syft:location:\d+:path$")

# bom-ref keys (1.4-1.6) for the generic ref clean-up of sections not rewritten explicitly.
REF_KEYS = frozenset({
    "ref", "dependsOn", "provides", "assemblies", "dependencies", "vulnerabilities",
    "subjects", "target", "claims", "counterClaims", "evidence", "counterEvidence",
    "mitigationStrategies", "requirement", "assessor", "source", "destination", "tools",
})

EXIT_OK = 0
EXIT_INPUT = 2
EXIT_INVALID = 3

CISA_WARNING = (
    "WARNING: --direct-only keeps only the root's direct dependencies. The result "
    "does not meet CISA 2026 SBOM Minimum Elements coverage, which expects "
    "transitive dependencies to be listed."
)


class TrimError(Exception):
    """Input or option error that should stop the run with a clear message."""


# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Pattern:
    """A component-matching pattern: shell glob by default, regex with ``re:``."""

    raw: str
    regex: Optional[re.Pattern[str]] = None

    @classmethod
    def parse(cls, raw: str) -> Pattern:
        """Build a pattern; ``re:<expr>`` is a regex (search), anything else a glob."""
        if raw.startswith("re:"):
            try:
                return cls(raw, re.compile(raw[3:]))
            except re.error as exc:
                raise TrimError(f"invalid regex in pattern {raw!r}: {exc}") from exc
        return cls(raw)

    def matches(self, value: str) -> bool:
        """Return True if ``value`` matches (glob: whole string, case-sensitive)."""
        if self.regex is not None:
            return self.regex.search(value) is not None
        return fnmatch.fnmatchcase(value, self.raw)


def match_component(comp: Dict[str, Any], patterns: List[Pattern]) -> Optional[Pattern]:
    """Return the first pattern matching the component's purl, group or name."""
    values = [comp.get(k) for k in ("purl", "group", "name")]
    for pat in patterns:
        if any(isinstance(v, str) and pat.matches(v) for v in values):
            return pat
    return None


# --------------------------------------------------------------------------- #
# Loading and Veracode helpers
# --------------------------------------------------------------------------- #


def load_bom(path: str) -> Dict[str, Any]:
    """Read and sanity-check a CycloneDX JSON or XML SBOM; raise TrimError otherwise."""
    return read_bom(path)[0]


def read_bom(path: str) -> Tuple[Dict[str, Any], str]:
    """Return ``(bom, input_format)``; XML is converted to the JSON model."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise TrimError(f"cannot read {path}: {exc}") from exc
    # PowerShell `>` writes UTF-16; honour BOMs, default UTF-8.
    if raw.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        enc = "utf-32"
    elif raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        enc = "utf-16"
    else:
        enc = "utf-8-sig"
    try:
        text = raw.decode(enc)
    except UnicodeDecodeError as exc:
        raise TrimError(f"cannot read {path}: not {enc.upper()} text ({exc.reason})") from exc
    stripped = text.lstrip()
    if stripped.startswith("SPDXVersion:"):
        raise TrimError("input is an SPDX tag-value document; only CycloneDX is supported")
    fmt = "xml" if stripped.startswith("<") else "json"
    if fmt == "xml":
        try:
            bom = xml_to_bom(text)
        except RecursionError as exc:
            raise TrimError("input XML is nested too deeply") from exc
    else:
        try:
            bom = json.loads(text, parse_constant=_reject_constant)
        except ValueError as exc:  # JSONDecodeError, >4300-digit ints, NaN/Infinity
            raise TrimError(f"input is not valid JSON: {exc}") from exc
        except RecursionError as exc:
            raise TrimError("input JSON is nested too deeply") from exc
    if not isinstance(bom, dict):
        raise TrimError("input is not a JSON object")
    if "spdxVersion" in bom or "SPDXID" in bom:
        raise TrimError(
            "input is an SPDX SBOM; SPDX is out of scope. Export CycloneDX from "
            "Veracode instead (SBOM API .../cyclonedx, srcclr --sbom cyclonedx1.6+json, "
            "or veracode sbom)"
        )
    if bom.get("bomFormat") != "CycloneDX":
        raise TrimError("input is not a CycloneDX SBOM (bomFormat != 'CycloneDX')")
    spec = bom.get("specVersion")
    if not isinstance(spec, str) or spec not in SUPPORTED_SPECS:
        shown = spec if isinstance(spec, str) else "(missing)" if spec is None else repr(spec)
        raise TrimError(
            f"CycloneDX specVersion {shown} is not supported; "
            f"supported: {', '.join(SUPPORTED_SPECS)}"
        )
    if not isinstance(bom.get("components", []), list):
        raise TrimError("'components' must be an array")
    if not isinstance(bom.get("dependencies", []), list):
        raise TrimError("'dependencies' must be an array")
    _check_shape(bom)
    return bom, fmt


def _reject_constant(token: str) -> Any:
    """json.loads hook: NaN/Infinity are not RFC 8259 JSON and break strict consumers."""
    raise ValueError(f"non-standard number {token} (NaN/Infinity are not allowed in JSON)")


def _is_ascii_digits(s: str) -> bool:
    """str.isdigit() also accepts '²' and other Unicode digits that int() rejects."""
    return s.isascii() and s.isdigit()


MAX_NESTING = 64  # nested components; real SBOMs use < 5
# Whole-document JSON depth: 64 nested components use ~130 levels. Deeper input
# would overflow recursion in deepcopy/jsonschema/XML output.
MAX_DEPTH = 2 * MAX_NESTING + 40


def _too_deep(node: Any, limit: int) -> bool:
    """True if dict/list nesting exceeds ``limit`` (iterative, so it cannot overflow)."""
    stack = [(node, 1)]
    while stack:
        value, depth = stack.pop()
        children = value.values() if isinstance(value, dict) else value
        for child in children:
            if isinstance(child, (dict, list)):
                if depth + 1 > limit:
                    return True
                stack.append((child, depth + 1))
    return False


def _check_shape(bom: Dict[str, Any]) -> None:
    """Reject wrong types in the fields trim() reads, with a JSON path (no tracebacks)."""
    if _too_deep(bom, MAX_DEPTH):
        raise TrimError(f"malformed SBOM: input is nested more than {MAX_DEPTH} levels deep")

    def need(cond: bool, path: str, what: str) -> None:
        if not cond:
            raise TrimError(f"malformed SBOM: {path} must be {what}")

    def opt(obj: Dict[str, Any], key: str, typ: Any, path: str, what: str) -> Any:
        val = obj.get(key)
        need(val is None or isinstance(val, typ), f"{path}.{key}", what)
        return val

    def items(obj: Dict[str, Any], key: str, path: str) -> List[Tuple[str, Dict[str, Any]]]:
        val = obj.get(key)
        need(key not in obj or isinstance(val, list), f"{path}.{key}", "an array")
        out = []
        for i, it in enumerate(val or []):
            need(isinstance(it, dict), f"{path}.{key}[{i}]", "an object")
            out.append((f"{path}.{key}[{i}]", it))
        return out

    def strs(obj: Dict[str, Any], key: str, path: str) -> None:
        val = opt(obj, key, list, path, "an array of strings")
        for i, s in enumerate(val or []):
            need(isinstance(s, str), f"{path}.{key}[{i}]", "a string")

    def component(path: str, c: Dict[str, Any], depth: int) -> None:
        if depth > MAX_NESTING:
            raise TrimError(f"malformed SBOM: components nested more than {MAX_NESTING} levels deep")
        for key in ("bom-ref", "name", "group", "version", "purl", "scope", "type"):
            opt(c, key, str, path, "a string")
        for p, prop in items(c, "properties", path):
            opt(prop, "name", str, p, "a string")
            opt(prop, "value", str, p, "a string")
        for p, child in items(c, "components", path):
            component(p, child, depth + 1)
        for p, svc in items(c, "services", path):
            component(p, svc, depth + 1)

    need(isinstance(bom.get("specVersion"), str), "$.specVersion", "a string")
    v = bom.get("version")
    need(v is None or (isinstance(v, int) and not isinstance(v, bool)), "$.version", "an integer")
    md = bom.get("metadata", {})
    need(isinstance(md, dict), "$.metadata", "an object")
    root = md.get("component")
    need("component" not in md or isinstance(root, dict), "$.metadata.component", "an object")
    if root:
        component("$.metadata.component", root, 0)
    tools = md.get("tools")
    need(tools is None or isinstance(tools, (list, dict)), "$.metadata.tools", "an array or object")
    if isinstance(tools, dict):
        items(tools, "components", "$.metadata.tools")
        items(tools, "services", "$.metadata.tools")
    elif isinstance(tools, list):
        for i, t in enumerate(tools):
            need(isinstance(t, dict), f"$.metadata.tools[{i}]", "an object")
    for p, c in items(bom, "components", "$"):
        component(p, c, 0)
    for p, s in items(bom, "services", "$"):
        component(p, s, 0)
    for p, d in items(bom, "dependencies", "$"):
        need(isinstance(d.get("ref"), str), f"{p}.ref", "a string")
        strs(d, "dependsOn", p)
        strs(d, "provides", p)
    for p, comp in items(bom, "compositions", "$"):
        strs(comp, "assemblies", p)
        strs(comp, "dependencies", p)
        strs(comp, "vulnerabilities", p)
    for p, vuln in items(bom, "vulnerabilities", "$"):
        for pa, a in items(vuln, "affects", p):
            need(isinstance(a.get("ref"), str), f"{pa}.ref", "a string")


# --------------------------------------------------------------------------- #
# CycloneDX XML <-> JSON model (stdlib only)
# Mapped per the 1.4-1.6 XSDs. Unmapped sections (modelCard, formulation, ...)
# use a generic mapping; if one breaks, validation fails and nothing is written.
# --------------------------------------------------------------------------- #

CDX_NS = "http://cyclonedx.org/schema/bom/"
# Prolog items allowed before the root element: whitespace/BOM, XML declaration, PIs, comments.
_XML_PROLOG_SKIP = re.compile(r"(?:[\s\ufeff]|<\?.*?\?>|<!--.*?-->)*", re.S)
# XML 1.0 NCName (element names without a prefix).
_NC_START = ("A-Z_a-z\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u02ff\u0370-\u037d\u037f-\u1fff"
             "\u200c\u200d\u2070-\u218f\u2c00-\u2fef\u3001-\ud7ff\uf900-\ufdcf\ufdf0-\ufffd"
             "\U00010000-\U000effff")
_XML_NCNAME = re.compile(f"[{_NC_START}][{_NC_START}\\-.0-9\u00b7\u0300-\u036f\u203f\u2040]*")

# wrapper element -> item element (both directions)
XML_ITEMS = {
    "components": "component", "services": "service", "externalReferences": "reference",
    "dependencies": "dependency", "compositions": "composition", "properties": "property",
    "vulnerabilities": "vulnerability", "hashes": "hash", "authors": "author",
    "lifecycles": "lifecycle", "annotations": "annotation", "references": "reference",
    "ratings": "rating", "cwes": "cwe", "advisories": "advisory", "versions": "version",
    "tags": "tag", "endpoints": "endpoint", "ancestors": "component", "descendants": "component",
    "variants": "component", "commits": "commit", "patches": "patch", "resolves": "issue",
    "aliases": "alias", "responses": "response", "organizations": "organization",
    "individuals": "individual", "supportingMaterial": "attachment", "affects": "target",
    "occurrences": "occurrence", "frames": "frame", "methods": "method",
}
# JSON key -> XML wrapper where names differ, per parent kind
XML_RENAME = {"analysis": {"response": "responses"}}
XML_ATTR_TYPES = {"tagVersion": int, "patch": bool}  # typed XML attributes (swid)
# wrappers whose items are bare refs: <assembly ref="x"/> <-> "x"
XML_REF_ITEMS = {"assemblies": "assembly", "subjects": "subject"}
# parent -> {element: list key} for repeated elements that have no wrapper
XML_UNWRAPPED = {
    "org": {"url": "url", "contact": "contact"},
    "dependency": {"dependency": "dependsOn", "provides": "provides"},
    "component": {"omniborId": "omniborId", "swhid": "swhid"},
}
XML_ORG = {"supplier", "manufacturer", "manufacture", "provider", "organization"}
XML_ATTRS = {
    "bom": ("serialNumber", "version"),
    "component": ("type", "mime-type", "bom-ref"),
    "reference": ("type",), "property": ("name",), "hash": ("alg",),
    "dependency": ("ref",), "provides": ("ref",), "assembly": ("ref",), "subject": ("ref",),
    "license": ("bom-ref", "acknowledgement"), "expression": ("bom-ref", "acknowledgement"),
    "swid": ("tagId", "name", "version", "tagVersion", "patch"),
    "patch": ("type",), "issue": ("type",), "classification": ("flow",),
    "text": ("content-type", "encoding"), "attachment": ("content-type", "encoding"),
}
XML_TEXT_KEY = {"property": "value", "hash": "content", "classification": "classification"}
XML_ATTR_JSON = {"content-type": "contentType"}  # XML attr -> JSON key when they differ
XML_INT = {"cwe"}
XML_FLOAT = {"score", "confidence"}
XML_BOOL = {"modified", "authenticated", "x-trust-boundary"}
# Element order (XSD sequences). Unlisted keys keep input order after these.
XML_ORDER = {
    "bom": ("metadata", "components", "services", "externalReferences", "dependencies",
            "compositions", "properties", "vulnerabilities", "annotations", "formulation",
            "declarations", "definitions"),
    "metadata": ("timestamp", "lifecycles", "tools", "authors", "component", "manufacturer",
                 "manufacture", "supplier", "licenses", "properties"),
    "component": ("supplier", "manufacturer", "authors", "author", "publisher", "group", "name",
                  "version", "description", "scope", "hashes", "licenses", "copyright", "cpe",
                  "purl", "omniborId", "swhid", "swid", "modified", "pedigree",
                  "externalReferences", "properties", "components", "evidence", "releaseNotes",
                  "modelCard", "data", "cryptoProperties", "tags"),
    "service": ("provider", "group", "name", "version", "description", "endpoints",
                "authenticated", "x-trust-boundary", "trustZone", "data", "licenses",
                "externalReferences", "properties", "services", "releaseNotes", "tags"),
    "org": ("name", "address", "url", "contact"),
    "contact": ("name", "email", "phone"),
    "license": ("id", "name", "text", "url", "licensing", "properties"),
    "reference": ("url", "comment", "hashes", "id", "source"),
    "tool": ("vendor", "name", "version", "hashes", "externalReferences"),
    "tools": ("components", "services"),
    "composition": ("aggregate", "assemblies", "dependencies", "vulnerabilities"),
    "vulnerability": ("id", "source", "references", "ratings", "cwes", "description", "detail",
                      "recommendation", "workaround", "proofOfConcept", "advisories", "created",
                      "published", "updated", "rejected", "credits", "tools", "analysis",
                      "affects", "properties"),
    "rating": ("source", "score", "severity", "method", "vector", "justification"),
    "source": ("name", "url"), "advisory": ("title", "url"),
    "analysis": ("state", "justification", "response", "detail", "firstIssued", "lastUpdated"),
    "target": ("ref", "versions"), "affected": ("version", "range", "status"),
    "credits": ("organizations", "individuals"),
    "proofOfConcept": ("reproductionSteps", "environment", "supportingMaterial"),
    "lifecycle": ("phase", "name", "description"),
    "annotation": ("subjects", "annotator", "timestamp", "text"),
    "pedigree": ("ancestors", "descendants", "variants", "commits", "patches", "notes"),
    "commit": ("uid", "url", "author", "committer", "message"),
    "releaseNotes": ("type", "title", "featuredImage", "socialImage", "description",
                     "timestamp", "aliases", "tags", "resolves", "notes", "properties"),
    "evidence": ("identity", "occurrences", "callstack", "licenses", "copyright"),
    "swid": ("text", "url"),
    "dependency": ("dependsOn", "provides"),
}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _uri_safe(purl: str) -> str:
    """Percent-encode chars xs:anyURI rejects (Syft puts pom ranges like @[1.0,) in purls)."""
    return "".join(c if c.isascii() and c not in ' []{}<>"\\^`|' else
                   "".join(f"%{b:02X}" for b in c.encode("utf-8")) for c in purl)


def _kind(tag: str, parent: str) -> str:
    """Schema type for ordering/attrs; same tag can mean different types."""
    if tag in XML_ORG:
        return "org"
    if tag in ("contact", "individual") or (tag == "author" and parent == "authors"):
        return "contact"
    if tag == "version" and parent == "versions":
        return "affected"
    return tag


def _scalar(tag: str, text: str) -> Any:
    try:
        if tag in XML_INT:
            return int(text)
        if tag in XML_FLOAT:
            num = float(text)
            return int(num) if num.is_integer() and "." not in text else num
    except ValueError:
        return text
    if tag in XML_BOOL:
        return text.strip().lower() == "true"
    return text


def _el_to_json(el: Any, parent: str, spec: str) -> Any:
    tag = _local(el.tag)
    kind = _kind(tag, parent)
    children = list(el)
    text = el.text or ""
    attrs = {XML_ATTR_JSON.get(k, k): v for k, v in el.attrib.items() if "}" not in k}
    if tag == "swid":
        for k, typ in XML_ATTR_TYPES.items():
            if k in attrs:
                attrs[k] = attrs[k] == "true" if typ is bool else _scalar("cwe", attrs[k])
    if "version" in attrs and tag == "bom":
        attrs["version"] = int(attrs["version"]) if _is_ascii_digits(attrs["version"]) else attrs["version"]
    # attachedText: always an object in JSON
    if tag in ("text", "attachment") and parent in ("license", "note", "diff", "supportingMaterial"):
        return {**attrs, "content": text}
    if not children:
        if attrs or tag in XML_TEXT_KEY:
            if text or tag in XML_TEXT_KEY:
                attrs[XML_TEXT_KEY.get(tag, "content")] = _scalar(tag, text)
            return attrs
        if kind in XML_ORDER and not text.strip():  # empty object, e.g. <supplier/>
            return {}
        return _scalar(tag, text)
    out: Dict[str, Any] = dict(attrs)
    unwrapped = XML_UNWRAPPED.get(kind, {})
    for child in children:
        ctag = _local(child.tag)
        if ctag in unwrapped:
            key = unwrapped[ctag]
            if kind == "dependency":  # <dependency ref="x"/> -> "x"
                out.setdefault(key, []).append(child.get("ref", ""))
            else:
                out.setdefault(key, []).append(_el_to_json(child, tag, spec))
            continue
        rename = {v: k for k, v in XML_RENAME.get(kind, {}).items()}
        out[rename.get(ctag, ctag)] = _child_to_json(child, ctag, tag, kind, spec)
    return out


def _child_to_json(child: Any, ctag: str, tag: str, kind: str, spec: str) -> Any:
    items = list(child)
    if ctag == "data" and kind == "service":  # <classification flow="x">PII</classification>
        return [{"flow": i.get("flow", ""), "classification": i.text or ""}
                if _local(i.tag) == "classification" else _el_to_json(i, "data", spec)
                for i in items]
    if ctag == "licenses":  # <license>/<expression> -> {"license": {...}} / {"expression": ...}
        res = []
        for it in items:
            itag = _local(it.tag)
            if itag == "expression":
                res.append({**{k: v for k, v in it.attrib.items()}, "expression": it.text or ""})
            else:
                res.append({"license": _el_to_json(it, "licenses", spec)})
        return res
    if ctag == "tools":  # legacy <tool> list vs 1.5+ {components, services}
        if items and all(_local(i.tag) == "tool" for i in items):
            return [_el_to_json(i, "tools", spec) for i in items]
        return {_local(i.tag): [_el_to_json(g, _local(i.tag), spec) for g in i] for i in items}
    if kind == "composition" and ctag in ("assemblies", "dependencies", "vulnerabilities"):
        return [i.get("ref", "") for i in items]
    if ctag in XML_REF_ITEMS:
        return [i.get("ref", "") for i in items]
    if ctag == "copyright" and kind == "evidence":
        return [{"text": i.text or ""} for i in items]
    if ctag == "notes" and kind == "releaseNotes":
        return [_el_to_json(i, "notes", spec) for i in items]
    if ctag == "references" and kind == "issue":
        return [i.text or "" for i in items]
    if ctag == "identity" and spec == "1.6":  # 1.6 made identity an array (unwrapped)
        return [_el_to_json(child, tag, spec)]
    if ctag in XML_ITEMS and (items or not child.attrib):
        return [_el_to_json(i, ctag, spec) for i in items]
    return _el_to_json(child, tag, spec)


def xml_to_bom(text: str) -> Dict[str, Any]:
    """CycloneDX 1.4-1.6 XML -> JSON-model dict."""

    # No XXE / billion laughs: a DOCTYPE (and so any ENTITY) can only sit in the
    # prolog, so refuse any "<!" markup there (any case). Expat rejects it later on.
    rest = text[_XML_PROLOG_SKIP.match(text).end():]  # type: ignore[union-attr]
    if rest.startswith("<!"):
        raise TrimError("input XML has a DOCTYPE/ENTITY declaration; refusing to parse")
    try:
        # Parse the decoded str: bytes would clash with a declared encoding="UTF-16".
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise TrimError(f"input is not valid XML: {exc}") from exc
    ns = root.tag[1:].split("}")[0] if root.tag.startswith("{") else ""
    if _local(root.tag) != "bom" or not ns.startswith(CDX_NS):
        raise TrimError("input XML is not a CycloneDX BOM (expected <bom xmlns="
                        f"\"{CDX_NS}1.x\">); SPDX is out of scope")
    spec = ns[len(CDX_NS):]
    body = _el_to_json(root, "", spec)
    bom: Dict[str, Any] = {
        "$schema": f"http://cyclonedx.org/schema/bom-{spec}.schema.json",
        "bomFormat": "CycloneDX", "specVersion": spec,
    }
    bom.update(body if isinstance(body, dict) else {})
    return bom


def _ordered(kind: str, value: Dict[str, Any]) -> List[str]:
    order = XML_ORDER.get(kind, ())
    known = [k for k in order if k in value]
    return known + [k for k in value if k not in order]


def _json_to_el(parent_el: Any, tag: str, value: Any, parent: str, ns: str) -> None:

    q = f"{{{ns}}}"
    kind = _kind(tag, parent)
    el = ET.SubElement(parent_el, q + tag)
    if not isinstance(value, dict):
        text = ("true" if value else "false") if isinstance(value, bool) else str(value)
        if tag == "purl":
            text = _uri_safe(text)
        el.text = text
        return
    attr_names = set(XML_ATTRS.get(tag, ())) | {"bom-ref"}
    text_key = XML_TEXT_KEY.get(tag, "content")
    json_to_attr = {v: k for k, v in XML_ATTR_JSON.items()}
    for key, val in value.items():
        xml_key = json_to_attr.get(key, key)
        if xml_key in attr_names and not isinstance(val, (dict, list)):
            el.set(xml_key, ("true" if val else "false") if isinstance(val, bool) else str(val))
    if text_key in value and not isinstance(value[text_key], (dict, list)) and (
            tag in XML_TEXT_KEY or tag in ("text", "attachment") or not set(value) - attr_names
            - {text_key} - set(XML_ATTR_JSON.values())):
        el.text = str(value[text_key])
        return
    unwrapped = {v: k for k, v in XML_UNWRAPPED.get(kind, {}).items()}
    for key in _ordered(kind, value):
        val = value[key]
        xml_key = json_to_attr.get(key, key)
        if xml_key in attr_names and not isinstance(val, (dict, list)):
            continue
        if key in unwrapped:
            for item in val if isinstance(val, list) else [val]:
                if kind == "dependency":
                    ET.SubElement(el, q + unwrapped[key]).set("ref", str(item))
                else:
                    _json_to_el(el, unwrapped[key], item, tag, ns)
            continue
        _json_child(el, key, val, tag, kind, ns)


def _json_child(el: Any, key: str, val: Any, tag: str, kind: str, ns: str) -> None:

    q = f"{{{ns}}}"
    if key == "data" and kind == "service" and isinstance(val, list):
        wrap = ET.SubElement(el, q + key)
        for item in val:
            if isinstance(item, dict) and set(item) <= {"flow", "classification"}:
                c = ET.SubElement(wrap, q + "classification")
                c.set("flow", str(item.get("flow", "")))
                c.text = str(item.get("classification", ""))
            else:
                _json_to_el(wrap, "dataflow", item, "data", ns)
        return
    key_xml = XML_RENAME.get(kind, {}).get(key)
    if key_xml and isinstance(val, list):
        wrap = ET.SubElement(el, q + key_xml)
        for item in val:
            _json_to_el(wrap, XML_ITEMS[key_xml], item, key_xml, ns)
        return
    if key == "licenses" and isinstance(val, list):
        wrap = ET.SubElement(el, q + key)
        for item in val:
            if isinstance(item, dict) and "expression" in item:
                ex = ET.SubElement(wrap, q + "expression")
                ex.text = str(item["expression"])
                for a in ("bom-ref", "acknowledgement"):
                    if a in item:
                        ex.set(a, str(item[a]))
            elif isinstance(item, dict):
                _json_to_el(wrap, "license", item.get("license", {}), "licenses", ns)
        return
    if key == "tools":
        wrap = ET.SubElement(el, q + key)
        if isinstance(val, list):
            for item in val:
                _json_to_el(wrap, "tool", item, "tools", ns)
        else:
            for sub in _ordered("tools", val):
                inner = ET.SubElement(wrap, q + sub)
                for item in val[sub]:
                    _json_to_el(inner, sub[:-1], item, sub, ns)
        return
    if isinstance(val, list):
        if kind == "composition" and key in ("assemblies", "dependencies", "vulnerabilities"):
            item_tag = {"assemblies": "assembly", "dependencies": "dependency",
                        "vulnerabilities": "vulnerability"}[key]
            wrap = ET.SubElement(el, q + key)
            for ref in val:
                ET.SubElement(wrap, q + item_tag).set("ref", str(ref))
            return
        if key in XML_REF_ITEMS:
            wrap = ET.SubElement(el, q + key)
            for ref in val:
                ET.SubElement(wrap, q + XML_REF_ITEMS[key]).set("ref", str(ref))
            return
        if key == "copyright" and kind == "evidence":
            wrap = ET.SubElement(el, q + key)
            for item in val:
                ET.SubElement(wrap, q + "text").text = str(item.get("text", ""))
            return
        if key == "identity":  # 1.6 array: repeated <identity>
            for item in val:
                _json_to_el(el, key, item, tag, ns)
            return
        item_tag = ("note" if key == "notes" else "url" if key == "references" and kind == "issue"
                    else XML_ITEMS.get(key, key[:-1] if key.endswith("s") else key))
        wrap = ET.SubElement(el, q + key)
        for item in val:
            _json_to_el(wrap, item_tag, item, key, ns)
        return
    _json_to_el(el, key, val, tag, ns)


def bom_to_xml(bom: Dict[str, Any], indent: int = 2) -> str:
    """JSON-model dict -> CycloneDX XML text for its specVersion."""

    ns = f"{CDX_NS}{bom.get('specVersion', '1.6')}"
    ET.register_namespace("", ns)
    holder = ET.Element("holder")
    body = {k: v for k, v in bom.items() if k not in ("$schema", "bomFormat", "specVersion")}
    _json_to_el(holder, "bom", body, "", ns)
    root = holder[0]
    prefix = f"{{{ns}}}"
    for el in root.iter():  # JSON keys become tags; ElementTree does not check names
        name = el.tag[len(prefix):] if el.tag.startswith(prefix) else el.tag
        if not (el.tag.startswith(prefix) and _XML_NCNAME.fullmatch(name)):
            raise ValueError(f"{name!r} is not a valid XML element name")
    if indent > 0:
        ET.indent(root, space=" " * indent)
    text = ET.tostring(root, encoding="unicode")
    bad = _XML_ILLEGAL.search(text)
    if bad:
        raise ValueError(f"character U+{ord(bad.group()):04X} is not allowed in XML 1.0")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + text + "\n"


# XML 1.0 forbids most C0 controls, surrogates and U+FFFE/U+FFFF.
_XML_ILLEGAL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def get_property(obj: Dict[str, Any], name: str) -> Optional[str]:
    """Value of the first CycloneDX property called ``name``, if any."""
    for prop in obj.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == name:
            value = prop.get("value")
            return value if isinstance(value, str) else None
    return None


def veracode_scan_type(bom: Dict[str, Any]) -> Optional[str]:
    """``application`` / ``agent`` from the root's ``veracode:scan_type`` property."""
    root = (bom.get("metadata") or {}).get("component")
    return get_property(root, VC_SCAN_TYPE) if isinstance(root, dict) else None


def is_unmatched(comp: Dict[str, Any]) -> bool:
    """True for files Veracode could not match to a known library."""
    return get_property(comp, VC_MATCH_TYPE) == VC_UNMATCHED


def is_path_property(name: Any) -> bool:
    """True for properties holding a file path that may name a containing file."""
    return isinstance(name, str) and (
        name in (VC_FILE_PATH, SYFT_VIRTUAL_PATH) or bool(SYFT_LOCATION_RE.match(name))
    )


def sbom_generator(bom: Dict[str, Any]) -> Optional[str]:
    """Best-effort source label: 'application'/'agent' (Veracode SCA) or 'syft'."""
    scan_type = veracode_scan_type(bom)
    if scan_type:
        return scan_type
    tools = (bom.get("metadata") or {}).get("tools")
    entries = tools if isinstance(tools, list) else (
        (tools.get("components") or []) if isinstance(tools, dict) else []
    )
    if any(isinstance(t, dict) and str(t.get("name", "")).lower() == "syft" for t in entries):
        return "syft"
    return None


# --------------------------------------------------------------------------- #
# Graph helpers
# --------------------------------------------------------------------------- #


def iter_components(
    comps: List[Dict[str, Any]], parent: Optional[Dict[str, Any]] = None
) -> Iterator[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]]:
    """Yield ``(component, parent)`` for every component, including nested ones."""
    for comp in comps or []:
        if not isinstance(comp, dict):
            continue
        yield comp, parent
        yield from iter_components(comp.get("components") or [], comp)


def _service_refs(services: List[Dict[str, Any]]) -> Set[str]:
    refs: Set[str] = set()
    for svc in services or []:
        if isinstance(svc, dict):
            if isinstance(svc.get("bom-ref"), str):
                refs.add(svc["bom-ref"])
            refs |= _service_refs(svc.get("services") or [])
    return refs


def build_graph(bom: Dict[str, Any]) -> Dict[str, List[str]]:
    """Map each ``dependencies[].ref`` to its ``dependsOn`` list."""
    graph: Dict[str, List[str]] = {}
    for entry in bom.get("dependencies") or []:
        ref = entry.get("ref") if isinstance(entry, dict) else None
        if isinstance(ref, str):
            graph.setdefault(ref, []).extend(
                t for t in entry.get("dependsOn") or [] if isinstance(t, str)
            )
    return graph


def edge_count(graph: Dict[str, List[str]]) -> int:
    """Number of dependsOn edges in the graph."""
    return sum(len(v) for v in graph.values())


def top_level_nodes(graph: Dict[str, List[str]], known: Optional[Set[str]] = None) -> Set[str]:
    """Graph nodes with no incoming edge.

    With ``known``, edges coming from nodes outside ``known`` (dangling refs that
    are not a component or the root) are ignored.
    """
    targets = {
        t for src, deps in graph.items() if known is None or src in known for t in deps
    }
    nodes = set(graph) | {t for deps in graph.values() for t in deps}
    return nodes - targets


def reachable(graph: Dict[str, List[str]], starts: Set[str], blocked: Set[str]) -> Set[str]:
    """Nodes reachable from ``starts`` without passing through ``blocked``."""
    seen: Set[str] = set()
    stack = [s for s in starts if s not in blocked]
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(t for t in graph.get(node, []) if t not in blocked and t not in seen)
    return seen


# --------------------------------------------------------------------------- #
# Options, report and run state
# --------------------------------------------------------------------------- #


@dataclass
class TrimOptions:
    """Which filters to apply."""

    runtime_only: bool = False
    drop_optional: bool = False
    excludes: List[Pattern] = field(default_factory=list)
    redacts: List[Pattern] = field(default_factory=list)
    direct_only: bool = False
    infer_direct: bool = False
    drop_unmatched: bool = False
    public_only: bool = False
    strip_paths: bool = False


@dataclass
class Report:
    """What the trim did, for ``--report`` and tests."""

    before: Dict[str, int] = field(default_factory=dict)
    after: Dict[str, int] = field(default_factory=dict)
    removed: List[Tuple[str, str]] = field(default_factory=list)  # (name@version, rule)
    redacted: List[Tuple[str, str]] = field(default_factory=list)  # (name@version, rule)
    removed_vulnerabilities: List[Tuple[str, str]] = field(default_factory=list)  # (id, reason)
    aggregate: Optional[str] = None
    scan_type: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    stripped_paths: int = 0

    def format(self) -> str:
        """Human-readable summary."""
        lines = ["sbom_trim report"]
        if self.scan_type:
            lines.append(f"SBOM source: {self.scan_type}")
        lines += ["", f"{'':16}{'before':>8}{'after':>8}"]
        for key in ("components", "dependencies", "vulnerabilities"):
            lines.append(f"{key:16}{self.before.get(key, 0):>8}{self.after.get(key, 0):>8}")
        lines.append("")
        lines.append(f"Removed components ({len(self.removed)}):")
        lines += [f"  - {label}  [{rule}]" for label, rule in self.removed] or ["  (none)"]
        lines.append(f"Redacted components ({len(self.redacted)}):")
        lines += [f"  - {label}  [{rule}]" for label, rule in self.redacted] or ["  (none)"]
        if self.removed_vulnerabilities:
            lines.append(f"Removed vulnerabilities ({len(self.removed_vulnerabilities)}):")
            lines += [f"  - {vid}  [{why}]" for vid, why in self.removed_vulnerabilities]
        if self.stripped_paths:
            lines.append(f"Path properties stripped: {self.stripped_paths}")
        lines.append(f"Composition aggregate for root: {self.aggregate or 'unchanged'}")
        lines += [f"Note: {w}" for w in self.warnings]
        return "\n".join(lines)


@dataclass
class _Decision:
    rule: str
    # Not external (public third-party): --exclude/--redact hits, Veracode-unmatched files.
    internal: bool
    hide: bool = False  # also hide its file name in other components' paths


@dataclass
class _Run:
    """Mutable state shared by the trim steps."""

    bom: Dict[str, Any]
    opts: TrimOptions
    report: Report
    root_ref: Optional[str]
    comps: List[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]]
    graph: Dict[str, List[str]]
    scan_type: Optional[str]
    removals: Dict[int, _Decision] = field(default_factory=dict)
    redactions: Dict[int, _Decision] = field(default_factory=dict)
    removed_refs: Set[str] = field(default_factory=set)
    redacted_old_refs: Set[str] = field(default_factory=set)
    remap: Dict[str, str] = field(default_factory=dict)


def _label(comp: Dict[str, Any]) -> str:
    name = comp.get("name", "?")
    if comp.get("group"):
        name = f"{comp['group']}:{name}"
    return f"{name}@{comp['version']}" if comp.get("version") else str(name)


def _counts(bom: Dict[str, Any]) -> Dict[str, int]:
    return {
        "components": sum(1 for _ in iter_components(bom.get("components") or [])),
        "dependencies": len(bom.get("dependencies") or []),
        "vulnerabilities": len(bom.get("vulnerabilities") or []),
    }


def _export_hint(scan_type: Optional[str]) -> str:
    if scan_type == "application":
        return " (Veracode Upload & Scan export, scan_type=application)"
    if scan_type == "agent":
        return " (Veracode agent export, scan_type=agent)"
    if scan_type == "syft":
        return " (Veracode CLI `veracode sbom` / Syft output)"
    return ""


# --------------------------------------------------------------------------- #
# Trim steps
# --------------------------------------------------------------------------- #


def _check_preconditions(run: _Run) -> Set[str]:
    """Validate options against the data; return the direct set for --direct-only."""
    opts, hint = run.opts, _export_hint(run.scan_type)
    if opts.drop_optional and not opts.runtime_only:
        raise TrimError("--drop-optional requires --runtime-only")
    if opts.infer_direct and not opts.direct_only:
        raise TrimError("--infer-direct requires --direct-only")
    if opts.public_only or opts.drop_unmatched:
        flag = "--public-only" if opts.public_only else "--drop-unmatched"
        if run.scan_type not in ("application", "agent"):
            raise TrimError(
                f"{flag} needs Veracode SCA match data (a Veracode SBOM REST API export, "
                f"whose root has 'veracode:scan_type'), and this SBOM has none{hint}. "
                "Tools like Syft give every file a purl, including your own artifacts, "
                "so public libraries cannot be told apart; use --exclude with your own "
                "group/purl patterns instead."
            )

    refs: List[str] = [c["bom-ref"] for c, _ in run.comps if isinstance(c.get("bom-ref"), str)]
    dupes = sorted(r for r, n in Counter(refs).items() if n > 1)
    if dupes:
        run.report.warnings.append(
            f"duplicate bom-refs in input (CycloneDX requires them to be unique): {', '.join(dupes[:5])}"
        )

    if opts.runtime_only and not any("scope" in c for c, _ in run.comps):
        raise TrimError(
            f"--runtime-only needs CycloneDX 'scope' on components, but none is set{hint}. "
            "Veracode SCA and Veracode CLI exports do not set scope. Refusing to pass everything "
            "through; drop --runtime-only."
        )
    if not opts.direct_only:
        return set()
    if edge_count(run.graph) == 0:
        extra = (
            " This export type contains no dependency graph; use an agent project "
            "export (SBOM API type=agent) for --direct-only."
            if run.scan_type in ("application", "syft") else ""
        )
        raise TrimError(
            f"--direct-only needs a dependency graph, but this SBOM has no "
            f"dependencies[].dependsOn edges{hint}.{extra}"
        )
    if not run.root_ref:
        raise TrimError("--direct-only needs metadata.component with a bom-ref (the root)")
    direct = set(run.graph.get(run.root_ref, []))
    if direct:
        return direct
    if not opts.infer_direct:
        raise TrimError(
            f"--direct-only: the root ({run.root_ref}) has no dependsOn entry, so its "
            f"direct dependencies are not recorded{hint}. Add --infer-direct to treat "
            "components with no incoming edge as direct dependencies (heuristic)."
        )
    component_refs = {c.get("bom-ref") for c, _ in run.comps}
    known = {r for r in component_refs if isinstance(r, str)} | {run.root_ref}
    direct = {n for n in top_level_nodes(run.graph, known) if n in component_refs}
    isolated = {n for n in direct if not run.graph.get(n)} - {
        t for deps in run.graph.values() for t in deps
    }
    run.report.warnings.append(
        f"--infer-direct treated {len(direct)} of {len(component_refs)} components as direct "
        f"(no incoming edge from another component). {len(isolated)} of them have no "
        "edges at all, so they may be direct or transitive with a missing edge."
    )
    return direct


def _decide(run: _Run, direct: Set[str]) -> None:
    """Assign a removal or redaction decision to each component."""
    opts = run.opts
    for comp, parent in run.comps:
        ref = comp.get("bom-ref")
        if run.root_ref and ref == run.root_ref:
            continue
        if parent is not None and id(parent) in run.removals:
            pd = run.removals[id(parent)]
            run.removals[id(comp)] = _Decision(f"parent removed ({_label(parent)})", pd.internal, pd.hide)
            continue
        pat = match_component(comp, opts.excludes)
        if pat:
            run.removals[id(comp)] = _Decision(f"exclude {pat.raw}", True, hide=True)
            continue
        if (opts.drop_unmatched or opts.public_only) and is_unmatched(comp):
            run.removals[id(comp)] = _Decision("not public (Veracode Match Type: Unmatched)", True)
            continue
        if opts.public_only and not comp.get("purl"):
            run.removals[id(comp)] = _Decision("not public (no purl from Veracode)", True)
            continue
        scope = comp.get("scope")
        if opts.runtime_only and scope == "excluded":
            run.removals[id(comp)] = _Decision("runtime-only (scope=excluded)", False)
            continue
        if opts.runtime_only and opts.drop_optional and scope == "optional":
            run.removals[id(comp)] = _Decision("runtime-only --drop-optional (scope=optional)", False)
            continue
        if opts.direct_only and ref not in direct:
            run.removals[id(comp)] = _Decision("direct-only (not a direct dependency of root)", False)
            continue
        pat = match_component(comp, opts.redacts)
        if pat:
            run.redactions[id(comp)] = _Decision(f"redact {pat.raw}", True, hide=True)
    run.removed_refs = {
        c["bom-ref"] for c, _ in run.comps
        if id(c) in run.removals and isinstance(c.get("bom-ref"), str)
    }


def _prune_orphans(run: _Run) -> None:
    """Remove components reachable before trimming but only through removed ones now."""
    if not run.removed_refs:
        return
    if edge_count(run.graph) == 0:
        if not run.opts.direct_only:
            run.report.warnings.append(
                "the SBOM has no dependency edges"
                f"{_export_hint(run.scan_type)}, so transitive dependencies of removed "
                "components cannot be identified and were kept"
            )
        return
    anchors = top_level_nodes(run.graph) | ({run.root_ref} if run.root_ref else set())
    before = reachable(run.graph, anchors, set())
    after = reachable(run.graph, anchors - run.removed_refs, run.removed_refs)
    orphans = (before - after) - run.removed_refs - anchors
    for comp, parent in run.comps:
        if id(comp) in run.removals:
            continue
        ref = comp.get("bom-ref")
        if ref in orphans:
            rule = "orphan (only reachable through removed components)"
            internal, hide = False, False
        elif parent is not None and id(parent) in run.removals:
            rule = f"parent removed ({_label(parent)})"
            internal, hide = run.removals[id(parent)].internal, run.removals[id(parent)].hide
        else:
            continue
        run.removals[id(comp)] = _Decision(rule, internal, hide)
        run.redactions.pop(id(comp), None)
        if isinstance(ref, str):
            run.removed_refs.add(ref)


def _check_duplicate_targets(run: _Run) -> None:
    counts = Counter(c.get("bom-ref") for c, _ in run.comps if isinstance(c.get("bom-ref"), str))
    touched = {
        c.get("bom-ref") for c, _ in run.comps if id(c) in run.removals or id(c) in run.redactions
    }
    clash = sorted(r for r in touched if isinstance(r, str) and counts[r] > 1)
    if clash:
        raise TrimError(
            "cannot trim safely: these bom-refs are shared by several components and at "
            f"least one of them is removed or redacted: {', '.join(clash[:5])}"
        )


def _scrub_file_paths(run: _Run) -> None:
    """Hide excluded/redacted files in other components' path properties.

    Veracode Upload & Scan (``File Path``) and the Veracode CLI / Syft
    (``syft:metadata:virtualPath``, ``syft:location:N:path``) nest files as
    ``outer.jar:inner.jar``; a kept inner jar would otherwise reveal the name of
    an excluded or redacted outer jar. Only --exclude/--redact hide names.
    """
    hidden: Dict[str, str] = {}  # hidden path -> replacement
    for comp, _ in run.comps:
        decision = run.removals.get(id(comp)) or run.redactions.get(id(comp))
        if not (decision and decision.hide):
            continue
        # The component's own (most specific) path; syft:location is the outer file.
        for path in (get_property(comp, VC_FILE_PATH), get_property(comp, SYFT_VIRTUAL_PATH)):
            if path:
                cut = max(path.rfind(sep) for sep in ("/", "\\", ":", "#")) + 1
                hidden.setdefault(path, path[:cut] + REDACTED_NAME)
    if not hidden:
        return
    for comp, _ in run.comps:
        if id(comp) in run.removals or id(comp) in run.redactions:
            continue
        for prop in comp.get("properties") or []:
            if not (isinstance(prop, dict) and is_path_property(prop.get("name"))):
                continue
            value = prop.get("value")
            if isinstance(value, str):
                new = _scrub_value(value, hidden)
                if new is not None:
                    prop["value"] = new


def _scrub_value(value: str, hidden: Dict[str, str]) -> Optional[str]:
    """Rewrite ``value`` if it is a hidden path or starts with one followed by ':' or '#'.

    The longest hidden prefix wins. Dict lookups per separator keep this
    O(len(value)) instead of O(hidden) per property.
    """
    if value in hidden:  # syft:location:N:path names the outer file itself
        return hidden[value]
    end = len(value)
    while True:
        end = max(value.rfind(":", 0, end), value.rfind("#", 0, end))
        if end <= 0:
            return None
        prefix = value[:end]
        if prefix in hidden:
            return hidden[prefix] + value[end:]


def _strip_paths(run: _Run) -> None:
    """Drop every build-path property (--strip-paths).

    Paths such as ``\\app\\target\\verademo\\WEB-INF\\lib\\x.jar`` reveal build
    layout and first-party names that no --exclude pattern can catch (the
    exploded ``verademo`` directory is not a component).
    """
    targets = [run.bom.get("metadata", {}).get("component")] + [c for c, _ in run.comps]
    for comp in targets:
        if not isinstance(comp, dict) or not isinstance(comp.get("properties"), list):
            continue
        kept = [p for p in comp["properties"]
                if not (isinstance(p, dict) and is_path_property(p.get("name")))]
        run.report.stripped_paths += len(comp["properties"]) - len(kept)
        if kept:
            comp["properties"] = kept
        else:
            del comp["properties"]


def _redact(comp: Dict[str, Any], new_ref: Optional[str]) -> None:
    """Replace a component in place with an anonymous placeholder."""
    original = dict(comp)
    comp.clear()
    for key, value in original.items():
        if key == "bom-ref":
            if new_ref is not None:
                comp["bom-ref"] = new_ref
        elif key == "name":
            comp["name"] = REDACTED_NAME
        elif key in REDACT_KEEP_FIELDS:
            comp[key] = value
    comp.setdefault("name", REDACTED_NAME)
    comp["properties"] = [{"name": REDACTED_PROPERTY, "value": "true"}]


def _apply_component_changes(run: _Run) -> None:
    """Record decisions, redact in place and drop removed components."""
    existing = {c.get("bom-ref") for c, _ in run.comps}
    counter = 0
    for comp, _ in run.comps:
        if id(comp) in run.removals:
            run.report.removed.append((_label(comp), run.removals[id(comp)].rule))
        elif id(comp) in run.redactions:
            run.report.redacted.append((_label(comp), run.redactions[id(comp)].rule))
            old_ref = comp.get("bom-ref")
            new_ref = None
            if isinstance(old_ref, str):
                counter += 1
                while f"redacted-{counter}" in existing:
                    counter += 1
                new_ref = f"redacted-{counter}"
                run.remap[old_ref] = new_ref
                run.redacted_old_refs.add(old_ref)
            _redact(comp, new_ref)

    def keep(items: List[Any]) -> List[Any]:
        kept = []
        for item in items:
            if id(item) in run.removals:
                continue
            if isinstance(item, dict) and isinstance(item.get("components"), list):
                item["components"] = keep(item["components"])
            kept.append(item)
        return kept

    if "components" in run.bom:
        run.bom["components"] = keep(run.bom["components"])


def _known_refs(run: _Run) -> Set[str]:
    """bom-refs that exist in the output (components, root, services)."""
    known = {
        c["bom-ref"] for c, _ in iter_components(run.bom.get("components") or [])
        if isinstance(c.get("bom-ref"), str)
    }
    root = (run.bom.get("metadata") or {}).get("component")
    if isinstance(root, dict):
        known |= {
            c["bom-ref"] for c, _ in iter_components([root]) if isinstance(c.get("bom-ref"), str)
        }
    return known | _service_refs(run.bom.get("services") or [])


def _rewrite_dependencies(run: _Run) -> None:
    """Drop entries/edges for removed or unknown refs, remap redacted refs."""
    if "dependencies" not in run.bom:
        return
    known = _known_refs(run)
    dangling: Set[str] = set()
    kept = []
    for entry in run.bom["dependencies"]:
        if not isinstance(entry, dict):
            continue
        old_ref = entry.get("ref")
        ref = run.remap.get(old_ref, old_ref) if isinstance(old_ref, str) else old_ref
        if old_ref in run.removed_refs:
            continue
        if ref not in known:
            dangling.add(str(ref))
            continue
        entry["ref"] = ref
        for key in ("dependsOn", "provides"):
            if not isinstance(entry.get(key), list):
                continue
            had = bool(entry[key])
            new = []
            for target in entry[key]:
                if target in run.removed_refs:
                    continue
                target = run.remap.get(target, target)
                if target not in known:
                    dangling.add(str(target))
                    continue
                new.append(target)
            entry[key] = new
            if had and not new:
                del entry[key]
        kept.append(entry)
    run.bom["dependencies"] = kept
    if dangling:
        run.report.warnings.append(
            "dropped dependency references to bom-refs that are not in the SBOM "
            f"(present in the input): {', '.join(sorted(dangling)[:5])}"
        )


def _rewrite_vulnerabilities(run: _Run) -> Set[str]:
    """Prune ``affects``; drop vulnerabilities left with nothing. Return their bom-refs."""
    removed_vuln_refs: Set[str] = set()
    if "vulnerabilities" not in run.bom:
        return removed_vuln_refs
    hidden_refs = run.removed_refs | run.redacted_old_refs
    redacted_hits: Dict[str, List[str]] = {}
    kept = []
    for vuln in run.bom["vulnerabilities"]:
        affects = vuln.get("affects") if isinstance(vuln, dict) else None
        vid = str(vuln.get("id", vuln.get("bom-ref", "?"))) if isinstance(vuln, dict) else "?"
        if isinstance(affects, list) and affects:
            new_affects, redacted_only = [], True
            for item in affects:
                ref = item.get("ref") if isinstance(item, dict) else None
                if ref in hidden_refs:
                    if ref in run.redacted_old_refs:
                        redacted_hits.setdefault(ref, []).append(vid)
                    else:
                        redacted_only = False
                    continue
                new_affects.append(item)
            if not new_affects:
                why = (
                    "affected only redacted components" if redacted_only
                    else "affected only removed components"
                )
                run.report.removed_vulnerabilities.append((vid, why))
                if isinstance(vuln.get("bom-ref"), str):
                    removed_vuln_refs.add(vuln["bom-ref"])
                continue
            vuln["affects"] = new_affects
        kept.append(vuln)
    run.bom["vulnerabilities"] = kept
    for old_ref, ids in redacted_hits.items():
        run.report.warnings.append(
            f"redacted component {run.remap.get(old_ref, old_ref)} has known vulnerabilities "
            f"({', '.join(sorted(set(ids))[:5])}), so it is a known library, not "
            "proprietary code. Its vulnerabilities were removed so they do not "
            "identify it; consider not redacting it."
        )
    return removed_vuln_refs


def _rewrite_other_refs(run: _Run, gone: Set[str]) -> None:
    """Remap/remove refs everywhere else (compositions, annotations, 1.5/1.6 sections)."""
    leftovers: Set[str] = set()

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in REF_KEYS:
                    if isinstance(value, str):
                        if value in run.remap:
                            node[key] = run.remap[value]
                        elif value in gone:
                            leftovers.add(path + "/" + key)
                        continue
                    if isinstance(value, list) and any(isinstance(v, str) for v in value):
                        new_list = []
                        for v in value:
                            if isinstance(v, str) and v in run.remap:
                                new_list.append(run.remap[v])
                            elif not (isinstance(v, str) and v in gone):
                                new_list.append(v)
                        node[key] = new_list
                        continue
                walk(value, path + "/" + key)
        elif isinstance(node, list):
            for item in node:
                walk(item, path + "[]")

    for section, value in run.bom.items():
        if section not in ("components", "dependencies", "vulnerabilities", "metadata"):
            walk(value, "/" + section)
    if leftovers:
        run.report.warnings.append(
            "references to removed components remain where they cannot be removed "
            f"automatically: {', '.join(sorted(leftovers)[:5])}"
        )


def _set_composition(run: _Run) -> None:
    """Record that the root's inventory and dependencies were trimmed.

    CycloneDX aggregate semantics (1.4-1.6): ``incomplete_third_party_only``
    means only third-party relationships are represented, which is the case when
    only non-external components were removed (``--exclude``/``--redact`` matches,
    Veracode-unmatched files). Anything else is ``incomplete``.
    """
    decisions = list(run.removals.values()) + list(run.redactions.values())
    if not decisions:
        return
    aggregate = (
        "incomplete_third_party_only" if all(d.internal for d in decisions) else "incomplete"
    )
    run.report.aggregate = aggregate
    compositions = run.bom.setdefault("compositions", [])
    if not run.root_ref:
        compositions.append({"aggregate": aggregate})
        run.report.warnings.append(
            "no root bom-ref in metadata.component; composition added without assemblies"
        )
        return
    kept = []
    for comp in compositions:
        lists = [k for k in ("assemblies", "dependencies") if isinstance(comp.get(k), list)]
        if any(run.root_ref in comp[k] for k in lists):
            for k in lists:
                comp[k] = [r for r in comp[k] if r != run.root_ref]
            if not any(comp.get(k) for k in ("assemblies", "dependencies", "vulnerabilities")):
                continue  # it described only the root; replaced below
        kept.append(comp)
    kept.append({
        "aggregate": aggregate,
        "assemblies": [run.root_ref],
        "dependencies": [run.root_ref],
    })
    run.bom["compositions"] = kept


def _update_metadata(bom: Dict[str, Any]) -> None:
    """New serialNumber, version + 1, timestamp now, this tool in metadata.tools."""
    bom["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    version = bom.get("version", 1)
    bom["version"] = (version if isinstance(version, int) and not isinstance(version, bool)
                      and version >= 1 else 1) + 1
    metadata = bom.setdefault("metadata", {})
    metadata["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tools = metadata.get("tools")
    if tools is None:
        # 1.4: array form only; 1.5+: object form.
        tools = [] if bom.get("specVersion") == "1.4" else {"components": []}
        metadata["tools"] = tools
    if isinstance(tools, list):  # keep the input's form; the two forms cannot be mixed
        if not any(isinstance(t, dict) and t.get("name") == TOOL_NAME
                   and t.get("version") == __version__ for t in tools):
            tools.append({"name": TOOL_NAME, "version": __version__})
    elif isinstance(tools, dict):
        comps = tools.setdefault("components", [])
        if not any(isinstance(c, dict) and c.get("name") == TOOL_NAME
                   and c.get("version") == __version__ for c in comps):
            comps.append({"type": "application", "name": TOOL_NAME, "version": __version__})


def trim(bom_in: Dict[str, Any], opts: TrimOptions) -> Tuple[Dict[str, Any], Report]:
    """Apply the selected filters and return ``(new_bom, report)``.

    The input dict is not modified. Raises TrimError when an option cannot be
    honoured with the data in the SBOM (no scope data, no dependency graph, ...).
    """
    bom = copy.deepcopy(bom_in)
    md = bom.get("metadata")
    metadata: Dict[str, Any] = md if isinstance(md, dict) else {}
    root = metadata.get("component") if isinstance(metadata.get("component"), dict) else None
    run = _Run(
        bom=bom,
        opts=opts,
        report=Report(before=_counts(bom), scan_type=sbom_generator(bom)),
        root_ref=root.get("bom-ref") if root and isinstance(root.get("bom-ref"), str) else None,
        comps=list(iter_components(bom.get("components") or [])),
        graph=build_graph(bom),
        scan_type=sbom_generator(bom),
    )
    direct = _check_preconditions(run)
    _decide(run, direct)
    _prune_orphans(run)
    _check_duplicate_targets(run)
    _scrub_file_paths(run)
    _apply_component_changes(run)
    if opts.strip_paths:
        _strip_paths(run)
    _rewrite_dependencies(run)
    removed_vulns = _rewrite_vulnerabilities(run)
    _rewrite_other_refs(run, run.removed_refs | run.redacted_old_refs | removed_vulns)
    _set_composition(run)
    _update_metadata(bom)
    run.report.after = _counts(bom)
    return bom, run.report


# --------------------------------------------------------------------------- #
# Validation, output and CLI
# --------------------------------------------------------------------------- #


def validate(text: str, spec_version: str, fmt: str = "json") -> Optional[str]:
    """Schema-validate output; None when valid.

    Raises ImportError when cyclonedx-python-lib[json-validation|xml-validation] is missing.
    """
    from cyclonedx.schema import SchemaVersion  # type: ignore

    if fmt == "xml":
        from cyclonedx.validation.xml import XmlValidator as Validator  # type: ignore
    else:
        fast = _fast_json_validator(spec_version)
        if fast is not None:
            error = next(iter(fast.iter_errors(json.loads(text))), None)
            return None if error is None else str(error)
        from cyclonedx.validation.json import JsonStrictValidator as Validator  # type: ignore
    error = Validator(SchemaVersion.from_version(spec_version)).validate_str(text)
    return None if error is None else str(error)


_FAST_VALIDATORS: Dict[str, Any] = {}


def _fast_json_validator(spec_version: str) -> Any:
    """cyclonedx's strict JSON validator with an O(n) ``uniqueItems``; None if unavailable.

    jsonschema checks ``uniqueItems`` pairwise (O(n^2): 10k components > 60 s).
    Same schema, registry and format checker, so accept/reject decisions and
    messages are unchanged. Uses library internals, hence the broad fallback.
    """
    if spec_version not in _FAST_VALIDATORS:
        fast = None
        try:
            from cyclonedx.schema import SchemaVersion  # type: ignore
            from cyclonedx.validation.json import JsonStrictValidator  # type: ignore
            from jsonschema.validators import extend  # type: ignore

            ref = JsonStrictValidator(SchemaVersion.from_version(spec_version))._validator
            cls = extend(type(ref), {"uniqueItems": _unique_items})
            fast = cls(ref.schema, registry=ref._registry, format_checker=ref.format_checker)
        except Exception:  # noqa: BLE001 - missing extra or changed internals: use the library path
            fast = None
        _FAST_VALIDATORS[spec_version] = fast
    return _FAST_VALIDATORS[spec_version]


def _unique_items(validator: Any, unique: Any, instance: Any, schema: Any) -> Iterator[Any]:
    """``uniqueItems`` keyword with a hash set; same message as jsonschema's."""
    if not (unique and validator.is_type(instance, "array")):
        return
    seen: Set[Any] = set()
    for item in instance:
        key = _json_key(item)
        if key in seen:
            from jsonschema.exceptions import ValidationError  # type: ignore

            yield ValidationError(f"{instance!r} has non-unique elements")
            return
        seen.add(key)


def _json_key(value: Any) -> Any:
    """Hashable key equal exactly when jsonschema's ``equal`` is (true != 1, 1 == 1.0)."""
    if isinstance(value, bool):
        return ("b", value)
    if isinstance(value, (int, float)):
        return ("n", value)
    if isinstance(value, str):
        return ("s", value)
    if isinstance(value, list):
        return ("l", tuple(_json_key(v) for v in value))
    if isinstance(value, dict):
        return ("d", frozenset((k, _json_key(v)) for k, v in value.items()))
    return ("o", value)


def _same_file(a: str, b: str) -> bool:
    if os.path.exists(a) and os.path.exists(b):
        return os.path.samefile(a, b)
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def write_json(path: str, text: str) -> None:
    """Write atomically (temp file in the same directory, then rename)."""
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        raise TrimError(f"output directory does not exist: {directory}")
    if os.path.isdir(path):
        raise TrimError(f"output path is a directory: {path}")
    fd, tmp = tempfile.mkstemp(prefix=".sbom_trim-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except OSError as exc:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise TrimError(f"cannot write {path}: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    """CLI definition."""
    p = argparse.ArgumentParser(
        prog="sbom_trim.py",
        description="Trim a Veracode SCA CycloneDX SBOM (JSON or XML).",
    )
    p.add_argument("input", help="CycloneDX JSON or XML SBOM from Veracode SCA")
    p.add_argument("-o", "--output", required=True, help="output path (never the input)")
    p.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="remove first-party components whose purl, group or name matches "
                        "(glob, or re:<regex>); repeatable")
    p.add_argument("--redact", action="append", default=[], metavar="PATTERN",
                   help="replace matching first-party components with a REDACTED placeholder; repeatable")
    p.add_argument("--drop-unmatched", action="store_true",
                   help="remove components Veracode marks 'Match Type: Unmatched' "
                        "(e.g. the scanned archive itself, <undefined> entries); "
                        "Veracode SBOM API exports only")
    p.add_argument("--public-only", action="store_true",
                   help="keep only components Veracode matched to a known public library "
                        "(has a purl, not Unmatched); Veracode SBOM API exports only")
    p.add_argument("--strip-paths", action="store_true",
                   help="remove build-path properties (Veracode 'File Path', Syft "
                        "syft:location:N:path / syft:metadata:virtualPath)")
    p.add_argument("--runtime-only", action="store_true",
                   help="drop components with scope 'excluded' (errors if the SBOM has no scope data)")
    p.add_argument("--drop-optional", action="store_true",
                   help="with --runtime-only, also drop scope 'optional'")
    p.add_argument("--direct-only", action="store_true",
                   help="keep only the root's direct dependencies (not CISA 2026 compliant)")
    p.add_argument("--infer-direct", action="store_true",
                   help="with --direct-only, treat components with no incoming edge as direct "
                        "when the root has no dependsOn (Veracode agent exports)")
    p.add_argument("--output-format", choices=("json", "xml"),
                   help="output format (default: same as input)")
    p.add_argument("--report", action="store_true", help="print a summary to stdout")
    p.add_argument("--no-validate", action="store_true", help="skip schema validation")
    p.add_argument("--indent", type=int, default=2, help="output indent (default 2)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point; returns the process exit code."""
    for stream in (sys.stdout, sys.stderr):
        # A cp1252 console/pipe (Windows, PYTHONUTF8=0) must not crash --report
        # after the output was written; unencodable characters become \uXXXX.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (ValueError, OSError):
                pass
    args = build_parser().parse_args(argv)
    try:
        if _same_file(args.input, args.output):
            raise TrimError("--output must differ from the input file; the input is never overwritten")
        bom, in_fmt = read_bom(args.input)
        out_fmt = args.output_format or in_fmt
        opts = TrimOptions(
            runtime_only=args.runtime_only,
            drop_optional=args.drop_optional,
            excludes=[Pattern.parse(x) for x in args.exclude],
            redacts=[Pattern.parse(x) for x in args.redact],
            direct_only=args.direct_only,
            infer_direct=args.infer_direct,
            drop_unmatched=args.drop_unmatched,
            public_only=args.public_only,
            strip_paths=args.strip_paths,
        )
        out, report = trim(bom, opts)
        if out_fmt == "xml":
            try:
                text = bom_to_xml(out, args.indent)
            except (TypeError, AttributeError, ValueError, KeyError, RecursionError) as exc:
                raise TrimError(f"cannot write XML: non-standard structure in the SBOM ({exc}); "
                                "use --output-format json") from exc
        else:
            try:  # allow_nan=False: NaN/Infinity (e.g. from an XML <score>NaN</score>) is not JSON
                text = json.dumps(out, indent=args.indent, ensure_ascii=False, allow_nan=False) + "\n"
                try:
                    text.encode("utf-8")
                except UnicodeEncodeError:  # lone surrogates from \uD800-style input escapes
                    text = json.dumps(out, indent=args.indent, allow_nan=False) + "\n"
            except ValueError as exc:
                raise TrimError(f"cannot write JSON: {exc}") from exc
        if not args.no_validate:
            try:
                error = validate(text, out["specVersion"], out_fmt)
            except ImportError:
                print(f"warning: cyclonedx-python-lib[{out_fmt}-validation] not installed; "
                      "schema validation skipped", file=sys.stderr)
            else:
                if error:
                    print(f"error: output failed CycloneDX {out['specVersion']} {out_fmt.upper()} "
                          f"schema validation; nothing written:\n{error}", file=sys.stderr)
                    return EXIT_INVALID
        write_json(args.output, text)
    except TrimError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except RecursionError:  # deep structures that slipped past _check_shape
        print("error: input is nested too deeply to process", file=sys.stderr)
        return EXIT_INPUT
    if args.direct_only:
        print(CISA_WARNING, file=sys.stderr)
    if args.report:
        print(report.format())  # includes the warnings as "Note:" lines
    else:
        for w in report.warnings:
            print(f"warning: {w}", file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
