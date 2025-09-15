#!.venv/bin/python3
import logging
import sys
import yaml

from argparse import ArgumentParser
from argparse import Namespace
from pathlib import Path

from sssig_rules import targets
from sssig_rules.schema import Rule
from sssig_rules.schema import Schema
from sssig_rules.targets import TargetKind

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


def main(args: list[str]) -> int:
    print(_translate(_parse_args(args)))
    return 0


def _translate(opts):
    fmt = opts.target
    rules = _load_rules(opts.rulespath)
    return getattr(targets, fmt).translate(rules)


def _load_rules(rulespath: Path) -> list[Rule]:
    with rulespath.open("r") as rulesfile:
        return Schema.model_validate(yaml.safe_load(rulesfile)).rules


def _parse_args(args: list[str]) -> Namespace:
    parser = ArgumentParser(
        prog="translate",
        description="translate rules",
    )
    parser.add_argument(
        "rulespath",
        type=Path,
    )
    parser.add_argument(
        "-t",
        "--target",
        type=TargetKind,
        choices=list(TargetKind),
        required=True,
    )

    opts = parser.parse_args(args)
    if not opts.rulespath.is_file():
        raise ValueError("provided rulespath does not exist")

    return opts


if __name__ == "__main__":
    main(sys.argv[1:])
