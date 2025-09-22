import enum

from enum import StrEnum
from typing import Annotated
from typing import Union
from typing import Literal

from pydantic import AfterValidator
from pydantic import BaseModel
from pydantic import BeforeValidator
from pydantic import Field
from pydantic import HttpUrl

from sssig_rules import hscheck  # type: ignore


def ensure_valid_range(value: int | list[int]) -> list[int]:
    if isinstance(value, int):
        return [value, value]

    if len(value) != 2:
        raise ValueError(f"{value} must contain two values")

    if value[0] >= value[1]:
        raise ValueError(f"the first number in {value} must be smaller")

    return value


def is_valid_hs_pattern(raw_pattern: str) -> str:
    """
    Make sure the pattern is a valid hyperscan pattern
    """
    err = hscheck.validate_pattern(raw_pattern)
    if err:
        raise ValueError(err)

    return raw_pattern


RuleId = Annotated[str, Field(pattern="^S3IG[A-Z2-7]{16}$")]
OptionalPositiveInt = Annotated[int | None, Field(ge=0)]
OptionalPositiveFloat = Annotated[float | None, Field(ge=0)]
VariableName = Annotated[str, Field(pattern="^[a-z](?:[a-z0-9_]*[a-z0-9])?$")]
Pattern = Annotated[str, AfterValidator(is_valid_hs_pattern)]


class Confidence(StrEnum):
    LOW = enum.auto()
    MEDIUM = enum.auto()
    HIGH = enum.auto()


class Syntax(StrEnum):
    HTML = enum.auto()
    JSON = enum.auto()
    XML = enum.auto()


class TargetKind(StrEnum):
    # The default kind if unset
    UNKNOWN = enum.auto()

    # Add types as needed and ensure the name is the official name used in the platform
    AWS_ACCESS_KEY_ID = enum.auto()
    AWS_SECRET_ACCESS_KEY = enum.auto()
    GITHUB_FINE_GRAINED_PERSONAL_ACCESS_TOKEN = enum.auto()
    GITHUB_PERSONAL_ACCESS_TOKEN = enum.auto()
    HOSTNAME = enum.auto()
    PASSWORD = enum.auto()
    USERNAME = enum.auto()


class Examples(BaseModel):
    positive: list[str] | None = None
    negative: list[str] | None = None


class Meta(BaseModel):
    # Rate the quality of the item
    confidence: Confidence | None = None
    # Provide pos/neg examples for this item
    examples: Examples | None = None
    # Provide references for how it was created
    references: list[HttpUrl] | None = None
    # Set whether or not the result of this should be included in the report
    report: bool = True
    # Tags for additional context and categorization
    tags: list[str] | None = None


class RuleMeta(Meta):
    kind: TargetKind = TargetKind.UNKNOWN
    name: str
    description: str | None = None


class Target(BaseModel):
    prefix_pattern: Pattern | None = None
    pattern: Pattern
    suffix_pattern: Pattern | None = None


class FilterKind(StrEnum):
    REQUIRE = enum.auto()
    EXCLUDE = enum.auto()


StatusRange = Annotated[list[int], BeforeValidator(ensure_valid_range)]


class HttpMatcher(BaseModel):
    statuses: list[StatusRange] | None = None
    headers: dict[str, list[str]] | None = None

    body_strings: list[str] | None = None
    body_patterns: list[Pattern] | None = None
    body_syntax: Syntax | None = None


class BaseFilter(BaseModel):
    """
    Filters options supported for all kinds
    """

    # Target features
    target_strings: list[str] | None = None

    # Path features
    path_patterns: list[Pattern] | None = None
    path_strings: list[str] | None = None

    # Context features (note: context may vary by target)
    context_strings: list[str] | None = None


class ExcludeFilter(BaseFilter):
    """
    Filters options supported only exclude
    """

    kind: Literal[FilterKind.EXCLUDE]

    # Target features
    target_patterns: list[Pattern] | None = None

    # Match features
    match_patterns: list[Pattern] | None = None
    match_strings: list[str] | None = None

    # Context features (note: context may vary by target)
    context_patterns: list[Pattern] | None = None


class RequireFilter(BaseFilter):
    """
    Filters options supported only require
    """

    kind: Literal[FilterKind.REQUIRE]

    # Target features
    target_min_entropy: OptionalPositiveFloat = None


Filter = Annotated[Union[ExcludeFilter, RequireFilter], Field(discriminator="kind")]


class AnalyzerKind(StrEnum):
    HTTP = enum.auto()


class AnalyzerMeta(Meta):
    kind: AnalyzerKind
    report: bool = False


class AnalyzerHttpAction(BaseModel):
    url: HttpUrl
    method: str | None = None
    headers: dict[str, str] | None = None
    body: str | None = None
    timeout: OptionalPositiveFloat = None


class Analyzer(BaseModel):
    meta: AnalyzerMeta
    action: AnalyzerHttpAction

    # these are AND'd
    condition: list[HttpMatcher]


class Dependancy(BaseModel):
    rule_id: RuleId
    varname: VariableName
    within_lines: OptionalPositiveInt = None
    within_columns: OptionalPositiveInt = None


class Rule(BaseModel):
    id: RuleId
    meta: RuleMeta
    dependencies: list[Dependancy] | None = None
    target: Target
    filters: list[Filter] | None = None
    analyzers: list[Analyzer] | None = None


class Schema(BaseModel):
    rules: list[Rule]
