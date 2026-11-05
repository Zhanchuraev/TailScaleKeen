"""Text parsing for the older iproute2 shipped by Keenetic (no `ip -j`)."""

import re, shlex


def route_rows(text):
    result = []
    for line in text.splitlines():
        words = shlex.split(line)
        if not words:
            continue
        row = {"type": "unicast"}
        if words[0] in [
            "unreachable",
            "blackhole",
            "prohibit",
            "throw",
            "local",
            "broadcast",
            "multicast",
            "unicast",
        ]:
            row["type"] = words.pop(0)
        if not words:
            continue
        row["dst"] = words[0]
        for key in ["dev", "via", "table", "scope", "metric"]:
            if key in words and words.index(key) + 1 < len(words):
                row["gateway" if key == "via" else key] = words[words.index(key) + 1]
        result.append(row)
    return result


def rule_rows(text):
    result = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+):\s*(.*)$", line)
        if not m:
            continue
        words = shlex.split(m[2])
        row = {"priority": int(m[1])}
        for key in ["fwmark", "iif", "lookup"]:
            if key in words and words.index(key) + 1 < len(words):
                row["table" if key == "lookup" else key] = words[words.index(key) + 1]
        if "fwmark" in row:
            mark, _, mask = row["fwmark"].partition("/")
            row["fwmark"] = mark
            row["fwmask"] = mask or "0xffffffff"
        result.append(row)
    return result
