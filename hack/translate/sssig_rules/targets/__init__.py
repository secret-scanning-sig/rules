import enum

from enum import StrEnum

from sssig_rules.targets import github as github
from sssig_rules.targets import gitleaks as gitleaks
from sssig_rules.targets import kingfisher as kingfisher
from sssig_rules.targets import noseyparker as noseyparker
from sssig_rules.targets import trufflehog as trufflehog


class TargetKind(StrEnum):
    GITHUB = enum.auto()
    GITLEAKS = enum.auto()
    KINGFISHER = enum.auto()
    NOSEYPARKER = enum.auto()
    TRUFFLEHOG = enum.auto()


__all__ = [kind.value for kind in TargetKind]
