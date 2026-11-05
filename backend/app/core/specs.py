"""Spec file formats owned by Asim, validated by Atta's engine.

* ``config/checks.yaml``       -- check specifications (docs/check-spec-format.md)
* ``config/cvss_mapping.yaml`` -- sensitivity class / body signal -> CR/IR/AR
* ``config/chains.yaml``       -- attack-chain templates
  (both: docs/cvss-mapping-contract.md)

Every model forbids unknown keys, so a typo fails validation instead of being
ignored. Load with :func:`load_checks`, :func:`load_cvss_mapping`,
:func:`load_chains`; they raise :class:`SpecError` with every problem listed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Discriminator,
    Field,
    Tag,
    ValidationError,
    field_validator,
    model_validator,
)

from app.core.contracts import BodySignal, ResponseInfo, SensitivityClass
from app.core.cvss import severity_for
from app.core.cvss31 import CvssVectorError, base_score, parse_base_vector
from app.db.models.enums import FindingCategory, Severity

CHECK_SPEC_VERSION = 1
CVSS_MAPPING_VERSION = 1
CHAINS_VERSION = 1  # format 1.1 (groups, scope, context, vectors) is additive

CheckId = Annotated[str, Field(pattern=r"^[A-Z]{3}-\d{3}$", examples=["HDR-001"])]
# OWASP API Security Top 10 2023 (API1-API10) or OWASP Top 10 2021/2025 (A01-A10).
OwaspId = Annotated[
    str,
    Field(
        pattern=r"^(API([1-9]|10):2023|A(0[1-9]|10):(2021|2025))$",
        examples=["API8:2023", "A02:2025"],
    ),
]
CweId = Annotated[str, Field(pattern=r"^CWE-[1-9]\d*$", examples=["CWE-319"])]


class SpecError(ValueError):
    """A spec file is missing, unparsable or invalid. ``problems`` lists each issue."""

    def __init__(self, path: Path | str, problems: Iterable[str]) -> None:
        self.path = str(path)
        self.problems = list(problems)
        super().__init__(f"{self.path}: " + "; ".join(self.problems))


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# Checks.yaml

HeaderOp = Literal[
    "missing", "present", "equals", "not_equals", "contains", "not_contains", "matches"
]
StatusOp = Literal["in", "not_in"]
BodyOp = Literal["contains", "not_contains", "matches", "not_empty", "json"]
HeaderNamesOp = Literal["none_match", "any_match"]
UrlOp = Literal["matches", "not_matches"]
_NO_VALUE_OPS = {"missing", "present"}
_NO_VALUE_BODY_OPS = {"not_empty", "json"}
_RULE_KINDS = ("header", "header_names", "status", "body", "url")


class HeaderRule(_Strict):
    """Condition on a response header (name is case-insensitive)."""

    header: str = Field(min_length=1, examples=["Strict-Transport-Security"])
    op: HeaderOp
    value: str | None = None
    case_sensitive: bool = False

    @model_validator(mode="after")
    def _value_matches_op(self) -> HeaderRule:
        if self.op in _NO_VALUE_OPS and self.value is not None:
            raise ValueError(f"op {self.op!r} takes no value")
        if self.op not in _NO_VALUE_OPS and not self.value:
            raise ValueError(f"op {self.op!r} needs a value")
        if self.op == "matches":
            _compile(self.value or "")
        return self

    def matches(self, response: ResponseInfo) -> bool:
        wanted = self.header.lower()
        actual = next((v for k, v in response.headers.items() if k.lower() == wanted), None)
        if self.op == "missing":
            return actual is None
        if self.op == "present":
            return actual is not None
        if actual is None:  # value comparisons need the header to exist
            return False
        expected = self.value or ""
        if self.op == "matches":
            flags = 0 if self.case_sensitive else re.IGNORECASE
            return re.search(expected, actual, flags) is not None
        value = actual.strip()
        if not self.case_sensitive:
            value, expected = value.lower(), expected.lower()
        if self.op == "equals":
            return value == expected
        if self.op == "not_equals":
            return value != expected
        if self.op == "contains":
            return expected in value
        return expected not in value  # not_contains


class StatusRule(_Strict):
    """Condition on the response status code."""

    status: StatusOp
    value: list[Annotated[int, Field(ge=100, le=599)]] = Field(min_length=1)

    def matches(self, response: ResponseInfo) -> bool:
        return (response.status_code in self.value) == (self.status == "in")


class BodyRule(_Strict):
    """Condition on the (truncated) response body. ``not_empty``: some
    non-whitespace text; ``json``: parses as a non-empty JSON object or array
    (both take no value; since 2026-11-05)."""

    body: BodyOp
    value: str | None = Field(None, min_length=1)

    @model_validator(mode="after")
    def _regex_compiles(self) -> BodyRule:
        if self.body in _NO_VALUE_BODY_OPS:
            if self.value is not None:
                raise ValueError(f"body op {self.body!r} takes no value")
            return self
        if not self.value:
            raise ValueError(f"body op {self.body!r} needs a value")
        if self.body == "matches":
            _compile(self.value)
        return self

    def matches(self, response: ResponseInfo) -> bool:
        if self.body == "not_empty":
            return bool(response.body.strip())
        if self.body == "json":
            try:
                parsed = json.loads(response.body)
            except ValueError:
                return False
            return isinstance(parsed, dict | list) and bool(parsed)
        value = self.value or ""
        if self.body == "matches":
            return re.search(value, response.body) is not None
        return (value in response.body) == (self.body == "contains")


class HeaderNamesRule(_Strict):
    """Condition on the set of response header names (since 2026-11-05):
    ``none_match`` fires when no header name matches the regex, e.g. no
    ``RateLimit-*``, ``X-RateLimit-*`` or ``Retry-After`` at all."""

    header_names: HeaderNamesOp
    value: str = Field(min_length=1)

    @model_validator(mode="after")
    def _regex_compiles(self) -> HeaderNamesRule:
        _compile(self.value)
        return self

    def matches(self, response: ResponseInfo) -> bool:
        hit = any(re.search(self.value, name, re.IGNORECASE) for name in response.headers)
        return hit == (self.header_names == "any_match")


class UrlRule(_Strict):
    """Condition on the final URL, after redirects (since 2026-11-05), e.g. "not
    redirected to a login page"."""

    url: UrlOp
    value: str = Field(min_length=1)

    @model_validator(mode="after")
    def _regex_compiles(self) -> UrlRule:
        _compile(self.value)
        return self

    def matches(self, response: ResponseInfo) -> bool:
        return (re.search(self.value, response.url) is not None) == (self.url == "matches")


def _compile(pattern: str) -> None:
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid regex {pattern!r}: {exc}") from exc


def _rule_kind(rule: Any) -> str | None:
    if isinstance(rule, dict):
        keys = [k for k in _RULE_KINDS if k in rule]
    else:
        keys = [k for k in _RULE_KINDS if hasattr(rule, k)]
    return keys[0] if len(keys) == 1 else None


Rule = Annotated[
    Annotated[HeaderRule, Tag("header")]
    | Annotated[HeaderNamesRule, Tag("header_names")]
    | Annotated[StatusRule, Tag("status")]
    | Annotated[BodyRule, Tag("body")]
    | Annotated[UrlRule, Tag("url")],
    Discriminator(_rule_kind),
]


class HttpCondition(_Strict):
    """When a check fires, evaluated against each in-scope response."""

    # Safe methods only: the scanner never sends state-changing requests.
    method: Literal["GET", "HEAD", "OPTIONS"] = "GET"
    # every_endpoint: each crawled endpoint; target_root: the scan URL only.
    scope: Literal["every_endpoint", "target_root"] = "every_endpoint"
    match: Literal["all", "any"] = "all"
    rules: list[Rule] = Field(min_length=1)

    @field_validator("rules", mode="before")
    @classmethod
    def _one_target_per_rule(cls, rules: Any) -> Any:
        for i, rule in enumerate(rules if isinstance(rules, list) else []):
            if isinstance(rule, dict):
                targets = [k for k in _RULE_KINDS if k in rule]
                if len(targets) != 1:
                    raise ValueError(
                        f"rule {i}: needs exactly one of {'/'.join(_RULE_KINDS)}, "
                        f"got {targets or 'none'}"
                    )
        return rules

    def matches(self, response: ResponseInfo) -> bool:
        """True when the check fires for ``response`` (all/any of the rules)."""
        results = (rule.matches(response) for rule in self.rules)
        return all(results) if self.match == "all" else any(results)


class AppliesToRule(_Strict):
    """One condition on the endpoint a check judges (exactly one key, except that
    ``methods`` narrows ``path``)."""

    # The endpoint's sensitivity class.
    sensitivity: list[SensitivityClass] | None = Field(None, min_length=1)
    # A keyword family the built-in path classifier matched (app/core/sensitivity.py).
    sensitivity_family: (
        Literal["identity", "payment", "secrets", "authentication", "account", "api", "public"]
        | None
    ) = None
    # A regex on the endpoint path, optionally only for these endpoint methods (a
    # POST form is judged on its GET response: the scanner never sends POST).
    path: str | None = None
    methods: list[Literal["GET", "POST", "PUT", "PATCH", "DELETE"]] | None = Field(
        None, min_length=1
    )
    # The request carried no Authorization header and no cookie.
    credentials: Literal["absent"] | None = None

    @model_validator(mode="after")
    def _one_condition(self) -> AppliesToRule:
        set_ = [
            k
            for k in ("sensitivity", "sensitivity_family", "path", "credentials")
            if getattr(self, k) is not None
        ]
        if len(set_) != 1:
            raise ValueError(
                "needs exactly one of sensitivity/sensitivity_family/path/credentials, "
                f"got {set_ or 'none'}"
            )
        if self.methods is not None and self.path is None:
            raise ValueError("'methods' only narrows a 'path' condition")
        if self.path is not None:
            _compile(self.path)
        return self


class AppliesTo(_Strict):
    """Which endpoints the check judges (since 2026-11-05; default: every one)."""

    match: Literal["all", "any"] = "all"
    rules: list[AppliesToRule] = Field(min_length=1)


class Artifact(_Strict):
    """The check is about a file at a path (since 2026-11-05). Such checks probe
    the target, so they never run in passive mode."""

    # Regex on the endpoint path: only matching endpoints are judged.
    path: str
    # Extra fixed paths requested from the target root (with the wordlist).
    probe: list[Annotated[str, Field(pattern=r"^/")]] = Field(default_factory=list)
    # An HTML body is the site's page, not the file.
    not_html: bool = True
    # Never fire on a response like the host's soft-404 baseline (a random path).
    not_soft_404: bool = True
    # The response must carry content (text or bytes; a .zip body decodes to "").
    require_body: bool = False

    @field_validator("path")
    @classmethod
    def _regex_compiles(cls, value: str) -> str:
        _compile(value)
        return value


class CheckSpec(_Strict):
    check_id: CheckId
    category: FindingCategory
    title: str | None = Field(None, max_length=255)
    description: str = Field(min_length=10)
    http_condition: HttpCondition
    owasp: list[OwaspId] = Field(min_length=1)
    cwe: list[CweId] = Field(min_length=1)
    base_cvss_vector: str
    recommendation: str | None = None
    references: list[str] = Field(default_factory=list)
    limitation: str | None = None
    # How context should move the severity (Contract 1 "severity notes"),
    # e.g. "raise with endpoint sensitivity". Guidance for the CVSS mapping.
    severity_notes: str | None = None
    applies_to: AppliesTo | None = None
    artifact: Artifact | None = None

    @field_validator("base_cvss_vector")
    @classmethod
    def _valid_vector(cls, vector: str) -> str:
        try:
            parse_base_vector(vector)
        except CvssVectorError as exc:
            raise ValueError(f"invalid CVSS v3.1 base vector: {exc}") from exc
        return vector

    @property
    def base_score(self) -> float:
        """Derived from the vector, so score and vector can never disagree."""
        return base_score(self.base_cvss_vector)


class CheckSpecFile(_Strict):
    spec_version: Literal[1]
    checks: list[CheckSpec] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_ids(self) -> CheckSpecFile:
        _reject_duplicates([c.check_id for c in self.checks], "check_id")
        return self


# Cvss_mapping.yaml

# CVSS v3.1 Security Requirements: L(ow), M(edium), H(igh), X (Not Defined).
Requirement = Literal["L", "M", "H", "X"]


class SecurityRequirements(_Strict):
    CR: Requirement
    IR: Requirement
    AR: Requirement


class CvssMapping(_Strict):
    mapping_version: Literal[1]
    sensitivity_classes: dict[SensitivityClass, SecurityRequirements]
    body_signals: dict[BodySignal, SecurityRequirements]
    # How the class and any detected signals combine, per requirement.
    combine: Literal["max"] = "max"

    @model_validator(mode="after")
    def _complete(self) -> CvssMapping:
        missing = [c.value for c in SensitivityClass if c not in self.sensitivity_classes]
        missing += [s.value for s in BodySignal if s not in self.body_signals]
        if missing:
            raise ValueError(f"every class and signal needs a row; missing: {', '.join(missing)}")
        return self


# Chains.yaml

ChainScope = Literal["same_endpoint", "same_host", "any_endpoint"]


class ChainSpec(_Strict):
    """An attack-chain template (docs/cvss-mapping-contract.md, section 3).

    Members are given either as ``groups`` (format 1.1: each group needs at
    least one finding) or, in the original style, as ``requires`` /
    ``mandatory`` / ``min_matches``. The score comes from
    ``composite_cvss_vector`` when present, so it stays a valid CVSS v3.1 score.
    """

    chain_id: Annotated[str, Field(pattern=r"^C\d{3}$", examples=["C005"])]
    name: str = Field(min_length=3, max_length=255)
    description: str = Field(min_length=10)
    # Format 1.1
    groups: list[Annotated[list[CheckId], Field(min_length=1)]] | None = None
    scope: ChainScope = "any_endpoint"
    endpoint_sensitivity: list[SensitivityClass] = Field(default_factory=list)
    body_signals: list[BodySignal] = Field(default_factory=list)
    composite_cvss_vector: str | None = None
    # Original style
    requires: list[CheckId] | None = None
    mandatory: list[CheckId] = Field(default_factory=list)
    min_matches: int | None = Field(None, ge=1)
    composite_score: float | None = Field(None, ge=0.0, le=10.0)
    severity: Severity

    @field_validator("composite_cvss_vector")
    @classmethod
    def _valid_vector(cls, vector: str | None) -> str | None:
        if vector is not None:
            try:
                parse_base_vector(vector)
            except CvssVectorError as exc:
                raise ValueError(f"invalid CVSS v3.1 base vector: {exc}") from exc
        return vector

    @model_validator(mode="after")
    def _consistent(self) -> ChainSpec:
        if (self.groups is None) == (self.requires is None):
            raise ValueError("use either groups or requires (with min_matches), not both")
        if self.groups is not None:
            if not self.groups:
                raise ValueError("groups needs at least one group")
            _reject_duplicates([c for g in self.groups for c in g], "groups entry")
        else:
            requires = self.requires or []
            if len(requires) < 2:
                raise ValueError("requires needs at least 2 checks")
            _reject_duplicates(requires, "requires entry")
            extra = sorted(set(self.mandatory) - set(requires))
            if extra:
                raise ValueError(f"mandatory checks must also be in requires: {extra}")
            if self.min_matches is None or not (
                len(self.mandatory) <= self.min_matches <= len(requires)
            ):
                raise ValueError("min_matches must be between len(mandatory) and len(requires)")
        if self.composite_cvss_vector is None and self.composite_score is None:
            raise ValueError("needs composite_cvss_vector or composite_score")
        if self.composite_cvss_vector is not None and self.composite_score is not None:
            derived = base_score(self.composite_cvss_vector)
            if derived != self.composite_score:
                raise ValueError(
                    f"composite_score {self.composite_score} does not match its "
                    f"vector ({derived}); leave it out"
                )
        if severity_for(self.score) != self.severity:
            raise ValueError(
                f"severity {self.severity.value} does not match the chain score "
                f"{self.score} ({severity_for(self.score).value})"
            )
        return self

    @property
    def score(self) -> float:
        """The chain's CVSS v3.1 score (from the vector when there is one)."""
        if self.composite_cvss_vector is not None:
            return base_score(self.composite_cvss_vector)
        return float(self.composite_score or 0.0)

    @property
    def member_ids(self) -> set[str]:
        if self.groups is not None:
            return {c for g in self.groups for c in g}
        return set(self.requires or [])


class ChainsFile(_Strict):
    chains_version: Literal[1]
    chains: list[ChainSpec] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_ids(self) -> ChainsFile:
        _reject_duplicates([c.chain_id for c in self.chains], "chain_id")
        return self


# Loading


def _reject_duplicates(values: list[str], what: str) -> None:
    dupes = sorted({v for v in values if values.count(v) > 1})
    if dupes:
        raise ValueError(f"duplicate {what}: {', '.join(dupes)}")


def _load(path: Path | str, model: type[BaseModel]) -> Any:
    p = Path(path)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SpecError(p, ["file not found"]) from None
    except yaml.YAMLError as exc:
        raise SpecError(p, [f"not valid YAML: {exc}"]) from exc
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise SpecError(p, [_describe(e) for e in exc.errors()]) from exc


def _describe(error: Any) -> str:
    loc = ".".join(str(part) for part in error["loc"]) or "(root)"
    return f"{loc}: {error['msg']}"


def load_checks(path: Path | str) -> CheckSpecFile:
    result: CheckSpecFile = _load(path, CheckSpecFile)
    return result


def load_cvss_mapping(path: Path | str) -> CvssMapping:
    result: CvssMapping = _load(path, CvssMapping)
    return result


def load_chains(
    path: Path | str,
    known_check_ids: Iterable[str] = (),
    member_scores: Mapping[str, float] | None = None,
) -> ChainsFile:
    """Load chains. With ``known_check_ids``, reject unknown check references; with
    ``member_scores`` (check id -> base score), require every chain to score above
    each of its members (SRS objective O4: composite > any member)."""
    chains: ChainsFile = _load(path, ChainsFile)
    known = set(known_check_ids)
    problems = []
    for c in chains.chains:
        problems += [
            f"chains.{c.chain_id}: unknown check {rid}"
            for rid in sorted(c.member_ids)
            if known and rid not in known
        ]
        scored = {
            rid: member_scores[rid]
            for rid in c.member_ids
            if member_scores and rid in member_scores
        }
        if scored and c.score <= max(scored.values()):
            top = max(scored, key=lambda k: scored[k])
            problems.append(
                f"chains.{c.chain_id}: score {c.score} must exceed every member "
                f"(highest: {top} {scored[top]})"
            )
    if problems:
        raise SpecError(path, problems)
    return chains
