import enum
import logging

from enum import StrEnum
from typing import Any

from pydantic import BaseModel

from sssig_rules.schema import FilterKind
from sssig_rules.schema import Rule
from sssig_rules.targets.common import _dump_json
from sssig_rules.targets.common import _or_patterns
from sssig_rules.targets.common import _strings_to_pattern

logger = logging.getLogger(__name__)


class _PostProcessingRule(StrEnum):
    MUST_MATCH = enum.auto()
    MUST_NOT_MATCH = enum.auto()


class _Config(BaseModel):
    patterns: list[dict[str, Any]]


def _pattern(rule: Rule) -> dict[str, Any]:
    values = {
        "secret_format": rule.target.pattern,
        "before_secret": rule.target.prefix_pattern,
        "after_secret": rule.target.suffix_pattern,
    }

    for i, f in enumerate(rule.filters or []):
        post_proc_patterns = []
        str_pattern = _strings_to_pattern(f.target_strings)
        if str_pattern:
            post_proc_patterns.append(str_pattern)

        match f.kind:
            case FilterKind.REQUIRE:
                post_proc_rule = _PostProcessingRule.MUST_MATCH
            case FilterKind.EXCLUDE:
                post_proc_rule = _PostProcessingRule.MUST_NOT_MATCH

                if f.target_patterns:
                    post_proc_patterns.extend(f.target_patterns)

        if not post_proc_patterns:
            logger.warning("skipping filter for rule: %s", rule.id)
            continue

        values[f"post_processing_{i}"] = _or_patterns(post_proc_patterns)
        values[f"post_processing_rule_{i}"] = post_proc_rule

    return values


def _config(rules: list[Rule]) -> _Config:
    return _Config(patterns=list(map(_pattern, rules)))


def translate(rules: list[Rule]) -> str:
    return _dump_json(_config(rules))
