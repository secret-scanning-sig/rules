import logging


from pydantic import BaseModel
from pydantic import HttpUrl

from sssig_rules.schema import Rule
from sssig_rules.schema import Pattern

from .common import _dump_yaml
from .common import _match_pattern

logger = logging.getLogger(__name__)


class _Rule(BaseModel):
    name: str
    id: str
    pattern: Pattern
    examples: list[str] | None = None
    negative_examples: list[str] | None = None
    categories: list[str] | None = None
    description: str | None = None
    references: list[HttpUrl] | None = None


def _examples(rule: Rule) -> list[str] | None:
    if rule.meta.examples:
        return rule.meta.examples.positive

    return None


def _negative_examples(rule: Rule) -> list[str] | None:
    if rule.meta.examples:
        return rule.meta.examples.negative

    return None


def _rule(rule: Rule) -> _Rule:
    if rule.dependencies:
        logger.warning(
            "rule.dependencies ignored in noseyparker: rule_id=%r",
            rule.id,
        )

    if rule.filters:
        logger.warning(
            "rule.filters ignored in noseyparker: rule_id=%r",
            rule.id,
        )

    if rule.analyzers:
        logger.warning(
            "rule.analyzers ignored in noseyparker: rule_id=%r",
            rule.id,
        )

    return _Rule(
        name=rule.meta.name,
        id=rule.id,
        pattern=_match_pattern(rule),
        examples=_examples(rule),
        negative_examples=_negative_examples(rule),
        categories=rule.meta.tags,
        description=rule.meta.description,
        references=rule.meta.references,
    )


class _Config(BaseModel):
    rules: list[_Rule]


def _config(rules: list[Rule]) -> _Config:
    return _Config(rules=list(map(_rule, rules)))


def translate(rules: list[Rule]) -> str:
    return _dump_yaml(_config(rules))
