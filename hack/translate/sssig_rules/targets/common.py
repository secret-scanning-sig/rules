import logging
import re
import json

import tomlkit
import yaml

from sssig_rules.schema import ExcludeFilter
from sssig_rules.schema import FilterKind
from sssig_rules.schema import Pattern
from sssig_rules.schema import RequireFilter
from sssig_rules.schema import Rule
from sssig_rules.util import yaml_dump

from pydantic import BaseModel

logger = logging.getLogger(__name__)


def _match_pattern(rule: Rule) -> Pattern:
    prefix = _pattern_str(rule.target.prefix_pattern, noncapture_group=True)
    suffix = _pattern_str(rule.target.suffix_pattern, noncapture_group=True)
    target = _pattern_str(rule.target.pattern, capture_group=bool(prefix or suffix))
    return Pattern(f"{prefix}{target}{suffix}")


def _pattern_str(
    pattern: Pattern | None,
    capture_group: bool = False,
    noncapture_group: bool = False,
) -> str:
    assert not (
        capture_group and noncapture_group
    ), "patterns can't be both capture groups and non-capture groups"

    if pattern is None:
        return ""
    elif capture_group:
        return f"({pattern})"
    elif noncapture_group:
        return f"(?:{pattern})"
    else:
        return str(pattern)


def _strings_to_pattern(strings: None | list[str]) -> Pattern | None:
    if strings is None:
        return None

    match len(strings):
        case 0:
            return None
        case 1:
            return Pattern(f"(?i){re.escape(strings[0]).lower()}")
        case _:
            return Pattern(
                "(?i)" + "|".join(f"(?:{re.escape(s).lower()})" for s in strings)
            )


def _or_patterns(patterns: list[Pattern]) -> Pattern | None:
    match len(patterns):
        case 0:
            return None
        case 1:
            return patterns[0]
        case _:
            return Pattern("|".join(f"(?:{p})" for p in patterns))


def _required_filters(rule: Rule) -> list[RequireFilter]:
    return [f for f in (rule.filters or []) if f.kind == FilterKind.REQUIRE]


def _excluded_filters(rule: Rule) -> list[ExcludeFilter]:
    return [f for f in (rule.filters or []) if f.kind == FilterKind.EXCLUDE]


def _min_entropy(rule: Rule) -> float | None:
    req_filters = _required_filters(rule)
    if not req_filters:
        return None

    entropy = 0.0
    for f in req_filters:
        if f.target_min_entropy and f.target_min_entropy > entropy:
            entropy = f.target_min_entropy

    return entropy or None


def _yaml_str_presenter(dumper, data):
    """
    Display multi-line values using |-
    """
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")

    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.add_representer(str, _yaml_str_presenter)


class _YamlDumper(yaml.Dumper):
    def ignore_aliases(self, *_):
        return True

    def increase_indent(self, flow=False, indentless=False):
        return super(_YamlDumper, self).increase_indent(flow, False)


def _dump_yaml(model: BaseModel) -> str:
    return yaml_dump(model.model_dump(mode="json", exclude_none=True))


def _dump_toml(model: BaseModel) -> str:
    return tomlkit.dumps(model.model_dump(mode="json", exclude_none=True))


def _dump_json(model: BaseModel) -> str:
    return json.dumps(
        model.model_dump(mode="json", exclude_none=True),
        indent=2,
    )
