import logging

from enum import StrEnum
from typing import Literal
from typing import Annotated
from typing import Union
from typing import overload


from pydantic import BaseModel
from pydantic import Field
from pydantic import HttpUrl

from sssig_rules.schema import Analyzer
from sssig_rules.schema import AnalyzerKind
from sssig_rules.schema import Confidence
from sssig_rules.schema import Pattern
from sssig_rules.schema import Rule
from sssig_rules.schema import Syntax
from sssig_rules.template import map_vars

from .common import _dump_yaml
from .common import _match_pattern
from .common import _min_entropy

logger = logging.getLogger(__name__)
valid_http_statuses = set(range(100, 600))
varmap = {
    "target": "TOKEN",
}


@overload
def _map_tmpl(tmpl: str) -> str: ...


@overload
def _map_tmpl(tmpl: None) -> None: ...


def _map_tmpl(tmpl: str | None) -> str | None:
    if tmpl is None:
        return None

    return map_vars(tmpl, varmap)


class _ValidationType(StrEnum):
    HTTP = "Http"


class _ResponseMatcherType(StrEnum):
    STATUS_MATCH = "StatusMatch"
    WORD_MATCH = "WordMatch"
    HEADER_MATCH = "HeaderMatch"
    JSON_VALID = "JsonValid"
    XML_VALID = "XmlValid"
    REPORT_RESPONSE = "ReportResponse"


class _StatusMatcher(BaseModel):
    type: Literal[_ResponseMatcherType.STATUS_MATCH] = _ResponseMatcherType.STATUS_MATCH
    status: list[int]
    negative: bool | None = None


class _WordMatcher(BaseModel):
    type: Literal[_ResponseMatcherType.WORD_MATCH] = _ResponseMatcherType.WORD_MATCH
    words: list[str]
    match_all_words: bool | None = None
    negative: bool | None = None


class _HeaderMatcher(BaseModel):
    type: Literal[_ResponseMatcherType.HEADER_MATCH] = _ResponseMatcherType.HEADER_MATCH
    header: str
    expected: list[str]


class _JsonValidMatcher(BaseModel):
    type: Literal[_ResponseMatcherType.JSON_VALID] = _ResponseMatcherType.JSON_VALID


class _XmlValidMatcher(BaseModel):
    type: Literal[_ResponseMatcherType.XML_VALID] = _ResponseMatcherType.XML_VALID


class _ReportResponseMatcher(BaseModel):
    type: Literal[_ResponseMatcherType.REPORT_RESPONSE] = (
        _ResponseMatcherType.REPORT_RESPONSE
    )
    report_response: bool | None = None


_ResponseMatcher = Annotated[
    Union[
        _StatusMatcher,
        _WordMatcher,
        _HeaderMatcher,
        _JsonValidMatcher,
        _XmlValidMatcher,
        _ReportResponseMatcher,
    ],
    Field(discriminator="type"),
]


class _Request(BaseModel):
    method: str
    url: HttpUrl
    headers: dict[str, str] | None = None
    body: str | None = None
    response_is_html: bool | None = None
    response_matcher: list[_ResponseMatcher] | None = None


class _ValidationContent(BaseModel):
    request: _Request


class _Validation(BaseModel):
    type: Literal[_ValidationType.HTTP]
    content: _ValidationContent


class _RuleRef(BaseModel):
    rule_id: str
    variable: str


class _Rule(BaseModel):
    name: str
    id: str
    pattern: Pattern
    min_entropy: float | None = None
    confidence: Confidence | None = None
    examples: list[str] | None = None
    references: list[HttpUrl] | None = None
    visibile: bool | None = None
    depends_on_rule: list[_RuleRef] | None = None
    validation: _Validation | None = None


class _Config(BaseModel):
    rules: list[_Rule]


def _response_is_html(analyzer: Analyzer) -> bool | None:
    for matcher in analyzer.condition:
        if matcher.body_syntax == Syntax.HTML:
            return True

    return None


def _resolve_status(statuses: list[list[int]]) -> tuple[bool, list[int]]:
    """
    Look at the statuses that would be passed in from the inclusive ranges
    and then expand those to a flat list of statuses.

    From that list determine if it would be fewer statuses to negate or not
    """
    expanded = {status for start, end in statuses for status in range(start, end + 1)}

    negated = valid_http_statuses - expanded
    if len(expanded) > len(negated):
        return True, list(negated)

    return False, list(expanded)


def _response_matcher(analyzer: Analyzer) -> list[_ResponseMatcher]:
    matchers: list[_ResponseMatcher] = []

    for matcher in analyzer.condition:
        if matcher.body_syntax == Syntax.JSON:
            matchers.append(_JsonValidMatcher())
        elif matcher.body_syntax == Syntax.XML:
            matchers.append(_XmlValidMatcher())

        if matcher.statuses:
            negative, status = _resolve_status(matcher.statuses)
            matchers.append(
                _StatusMatcher(
                    status=status,
                    negative=negative,
                )
            )

        if matcher.headers:
            for header, values in matcher.headers.items():
                matchers.append(
                    _HeaderMatcher(
                        header=header.title(),
                        expected=values,
                    )
                )

    if analyzer.meta.report:
        matchers.append(
            _ReportResponseMatcher(
                report_response=analyzer.meta.report,
            )
        )

    return matchers


def _validation(rule: Rule) -> _Validation | None:
    if not rule.analyzers:
        return None

    http_analyzers = [a for a in rule.analyzers if a.meta.kind == AnalyzerKind.HTTP]
    unused_analyzer_count = len(rule.analyzers) - int(bool(http_analyzers))
    if unused_analyzer_count > 0:
        logging.warning("%d analyzers not mapped for this rule", unused_analyzer_count)

    if not http_analyzers:
        return None

    analyzer = http_analyzers[0]
    if analyzer.action.timeout:
        logger.warning("HTTP analyzer timeout ignored")

    def map_headers(f, d):
        return {k.title(): f(v) for k, v in (d or {}).items()}

    validation = _Validation(
        type=_ValidationType.HTTP,
        content=_ValidationContent(
            request=_Request(
                method=(analyzer.action.method or "GET").upper(),
                url=HttpUrl(_map_tmpl(str(analyzer.action.url))),
                headers=map_headers(_map_tmpl, analyzer.action.headers) or None,
                body=_map_tmpl(analyzer.action.body),
                response_is_html=_response_is_html(analyzer),
                response_matcher=_response_matcher(analyzer),
            )
        ),
    )

    return validation


def _examples(rule: Rule) -> list[str] | None:
    if rule.meta.examples:
        return rule.meta.examples.positive

    return None


def _depends_on_rule(rule: Rule) -> list[_RuleRef] | None:
    if not rule.dependencies:
        return None

    return [
        _RuleRef(
            rule_id=dep.rule_id,
            variable=dep.varname,
        )
        for dep in rule.dependencies
    ]


def _rule(rule: Rule) -> _Rule:
    if rule.filters:
        logger.warning(
            "rule.filters ignored in kingfisher: rule_id=%r",
            rule.id,
        )

    return _Rule(
        name=rule.meta.name,
        id=rule.id,
        pattern=_match_pattern(rule),
        min_entropy=_min_entropy(rule),
        confidence=rule.meta.confidence,
        examples=_examples(rule),
        references=rule.meta.references,
        visibile=rule.meta.report,
        depends_on_rule=_depends_on_rule(rule),
        validation=_validation(rule),
    )


def _config(rules: list[Rule]) -> _Config:
    return _Config(rules=list(map(_rule, rules)))


def translate(rules: list[Rule]) -> str:
    return _dump_yaml(_config(rules))
