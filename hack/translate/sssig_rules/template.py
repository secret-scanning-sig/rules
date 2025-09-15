"""
A module for parsing and serializing liquid templates.
"""

import liquid  # type: ignore

from liquid.builtin.expressions.path import Path  # type: ignore


def map_vars(tmpl: str, varmap: dict[str, str]) -> str:
    """
    this allows mapping vars in liquid templates. The reason is the
    source template has some built in vars that might not map to the same
    thing for different targets. This allows you to update those variables
    references.
    """
    tokens_to_replace = [
        (t.start_index, t.value)
        for node in liquid.parse(tmpl).nodes
        for expr in node.expressions()
        for child in expr.children()
        if (
            isinstance(child, Path)
            and (t := child.token)
            and t.kind == "word"
            and t.value in varmap
        )
    ]

    def replace(parts: list[str], start: int, tkns: list[tuple[int, str]]) -> str:
        if not len(tkns):
            return "".join(parts + [tmpl[start:]])

        end, val = tkns[0]
        between = tmpl[start:end]
        replaced = varmap[val]
        return replace(parts + [between, replaced], end + len(val), tkns[1:])

    return replace([], 0, tokens_to_replace)
