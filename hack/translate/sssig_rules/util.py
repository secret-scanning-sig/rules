import yaml

from typing import Any


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


def yaml_dump(data: Any) -> str:
    return yaml.dump(
        data,
        Dumper=_YamlDumper,
        sort_keys=False,
        default_flow_style=False,
        width=float("inf"),
    )
