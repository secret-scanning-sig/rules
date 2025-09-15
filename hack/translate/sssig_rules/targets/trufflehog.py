import logging

from pydantic import BaseModel
from pydantic import HttpUrl

from sssig_rules.schema import AnalyzerKind
from sssig_rules.schema import Pattern
from sssig_rules.schema import Rule

from .common import _dump_yaml
from .common import _excluded_filters
from .common import _match_pattern
from .common import _min_entropy
from .common import _required_filters
from .common import _strings_to_pattern

logger = logging.getLogger(__name__)


class _Verify(BaseModel):
    endpoint: HttpUrl
    unsafe: bool | None = None
    headers: list[str] | None = None


class _Detector(BaseModel):
    name: str
    keywords: list[str] | None = None
    regex: dict[str, Pattern]
    entropy: float | None = None
    exclude_words: list[str] | None = None
    exclude_regexes_match: list[Pattern] | None = None
    verify: list[_Verify] | None = None


class _Config(BaseModel):
    detectors: list[_Detector]


def _keywords(rule: Rule) -> list[str] | None:
    req_filters = _required_filters(rule)
    if not req_filters:
        return None

    keywords = []
    for f in req_filters:
        if f.context_strings:
            keywords.extend(f.context_strings)

        if f.target_strings:
            keywords.extend(f.target_strings)

    return keywords or None


def _exclude_words(rule: Rule) -> list[str] | None:
    exc_filters = _excluded_filters(rule)
    if not exc_filters:
        return None

    words = [word for f in exc_filters if f.target_strings for word in f.target_strings]

    return words or None


def _exclude_regexes_match(rule: Rule) -> list[Pattern] | None:
    exc_filters = _excluded_filters(rule)
    if not exc_filters:
        return None

    patterns = []
    for f in exc_filters:
        if f.match_patterns:
            patterns.extend(f.match_patterns)
        if f.match_strings:
            string_pattern = _strings_to_pattern(f.match_strings)
            if string_pattern:
                patterns.append(string_pattern)

    return patterns or None


def _verify(rule: Rule) -> list[_Verify] | None:
    if not rule.analyzers:
        return None

    verifiers = []
    for analyzer in rule.analyzers:
        if analyzer.meta.kind != AnalyzerKind.HTTP:
            logger.warning(
                "unsupported analyzer kind for trufflehog verify: %s",
                analyzer.meta.kind,
            )
            continue

        verifiers.append(
            _Verify(
                endpoint=analyzer.action.url,
                unsafe=analyzer.action.url.scheme == "http" or None,
                headers=(
                    None
                    if not analyzer.action.headers
                    else [f"{k}: {v}" for k, v in analyzer.action.headers.items()]
                ),
            )
        )

    return verifiers or None


def _detector(rule: Rule) -> _Detector:
    return _Detector(
        name=rule.id,
        keywords=_keywords(rule),
        regex={"target": _match_pattern(rule)},
        entropy=_min_entropy(rule),
        exclude_words=_exclude_words(rule),
        exclude_regexes_match=_exclude_regexes_match(rule),
        verify=_verify(rule),
    )


def _config(rules: list[Rule]) -> _Config:
    return _Config(detectors=[_detector(rule) for rule in rules])


def translate(rules: list[Rule]) -> str:
    """
    Translate a list of generic rules to a TruffleHog configuration.
    """
    return _dump_yaml(_config(rules))
