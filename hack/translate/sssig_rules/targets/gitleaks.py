import enum
import logging

from enum import StrEnum

from pydantic import BaseModel

from sssig_rules.schema import ExcludeFilter
from sssig_rules.schema import Filter
from sssig_rules.schema import OptionalPositiveFloat
from sssig_rules.schema import OptionalPositiveInt
from sssig_rules.schema import Pattern
from sssig_rules.schema import Rule

from .common import _dump_toml
from .common import _excluded_filters
from .common import _match_pattern
from .common import _min_entropy as _entropy
from .common import _or_patterns
from .common import _required_filters
from .common import _strings_to_pattern

logger = logging.getLogger(__name__)


class _RegexTarget(StrEnum):
    LINE = enum.auto()
    MATCH = enum.auto()
    SECRET = enum.auto()


class _AllowlistCondition(StrEnum):
    AND = enum.auto()
    OR = enum.auto()


class _Allowlist(BaseModel):
    condition: _AllowlistCondition
    regexTarget: _RegexTarget | None = None
    paths: list[Pattern] | None = None
    regexes: list[Pattern] | None = None
    stopwords: list[str] | None = None


class _Required(BaseModel):
    id: str
    withinLines: OptionalPositiveInt = None
    withinColumns: OptionalPositiveInt = None


class _Rule(BaseModel):
    id: str
    description: str | None = None
    path: Pattern | None = None
    regex: Pattern | None = None
    entropy: OptionalPositiveFloat = None
    keywords: list[str] | None = None
    tags: list[str] | None = None
    skipReport: bool | None = None
    allowlists: list[_Allowlist] | None = None
    required: list[_Required] | None = None


class _Config(BaseModel):
    rules: list[_Rule]


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


def _regex(rule: Rule) -> Pattern:
    return _match_pattern(rule)


def _path_patterns(f: Filter) -> list[Pattern] | None:
    patterns = []

    if f.path_patterns:
        patterns.extend(f.path_patterns)

    strings_pattern = _strings_to_pattern(f.path_strings)
    if strings_pattern is not None:
        patterns.append(strings_pattern)

    return patterns or None


def _path(rule: Rule) -> Pattern | None:
    pattern_lists: list[list[Pattern]] = []
    for f in _required_filters(rule):
        patterns = _path_patterns(f)
        if patterns is not None:
            pattern_lists.append(patterns)
    return _or_patterns([p for ps in pattern_lists for p in ps])


def _tags(rule: Rule) -> list[str]:
    tags = [
        f"kind:{rule.meta.kind}",
    ]

    if rule.meta.confidence:
        tags.append(f"confidence:{rule.meta.confidence}")

    if rule.meta.tags:
        tags.extend(rule.meta.tags)

    return tags


def _required(rule: Rule) -> list[_Required] | None:
    if not rule.dependencies:
        return None

    return [
        _Required(
            id=d.rule_id,
            withinLines=d.within_lines,
            withinColumns=d.within_columns,
        )
        for d in rule.dependencies
    ]


def _id(rule: Rule) -> str:
    return rule.id


def _description(rule: Rule) -> str | None:
    return rule.meta.description or rule.meta.name


def _skip_report(rule: Rule) -> bool:
    return not rule.meta.report


def _allowlist_regexes(
    rule: Rule, f: ExcludeFilter
) -> tuple[_RegexTarget | None, list[Pattern] | None]:
    # Gitleaks can't handle multiple allowlist pattern scopes AND'd together
    # so this tries to do the best it can to set the target correctly when
    # there are multiple scopes in the same rule
    patterns: list[Pattern] = []
    regex_target: _RegexTarget | None = None

    if f.context_patterns or f.context_strings:
        regex_target = _RegexTarget.LINE

        if f.context_patterns:
            patterns.extend(f.context_patterns)

        strings_pattern = _strings_to_pattern(f.context_strings)
        if strings_pattern is not None:
            patterns.append(strings_pattern)

    if f.match_patterns or f.match_strings:
        if regex_target:
            logger.warning(
                "applying match patterns with a '%s' regex target", regex_target
            )
        else:
            regex_target = _RegexTarget.MATCH

        if f.match_patterns:
            patterns.extend(f.match_patterns)

        strings_pattern = _strings_to_pattern(f.match_strings)
        if strings_pattern is not None:
            patterns.append(strings_pattern)

    if f.target_patterns:
        if regex_target:
            logger.warning(
                "applying target patterns with a '%s' regex target", regex_target
            )
        else:
            regex_target = _RegexTarget.SECRET

        if f.target_patterns:
            patterns.extend(f.target_patterns)

    if not patterns:
        return None, None

    return regex_target, patterns


def _allowlists(rule: Rule) -> list[_Allowlist] | None:
    exc_filters = _excluded_filters(rule)
    if not exc_filters:
        return None

    allowlists = []
    for f in exc_filters:
        regex_target, patterns = _allowlist_regexes(rule, f)
        allowlists.append(
            _Allowlist(
                condition=_AllowlistCondition.AND,
                stopwords=f.target_strings,
                paths=_path_patterns(f),
                regexes=patterns,
                regexTarget=regex_target,
            )
        )

    return allowlists or None


def _rule(rule: Rule) -> _Rule:
    if rule.analyzers is not None:
        logger.warning(
            "rule.analyzers ignored in gitleaks: rule_id=%r",
            rule.id,
        )

    return _Rule(
        id=_id(rule),
        description=_description(rule),
        path=_path(rule),
        regex=_regex(rule),
        entropy=_entropy(rule),
        keywords=_keywords(rule),
        tags=_tags(rule),
        required=_required(rule),
        allowlists=_allowlists(rule),
        skipReport=_skip_report(rule),
    )


def _config(rules: list[Rule]) -> _Config:
    return _Config(rules=list(map(_rule, rules)))


def translate(rules: list[Rule]) -> str:
    return _dump_toml(_config(rules))
