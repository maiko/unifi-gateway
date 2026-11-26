"""Read and update explicitly reserved VyOS firewall rule numbers."""

import re


def reserved_rules(current, paths, rule_base, preparation_slots):
    if not isinstance(current, dict) or current.keys() != paths.keys():
        raise ValueError("Guard planning requires complete firewall chains")
    slots = {str(rule_base + offset) for offset in range(preparation_slots)}
    selected = {}
    for name, rules in current.items():
        if not isinstance(rules, dict) or any(
            not isinstance(slot, str) or re.fullmatch(r"[1-9][0-9]{0,6}", slot) is None
            or not isinstance(rule, dict) for slot, rule in rules.items()
        ):
            raise ValueError("VyOS returned an invalid firewall rule collection")
        selected[name] = {slot: rule for slot, rule in rules.items() if slot in slots}
    return selected


def firewall_rule_changes(paths, owned, desired):
    commands = []
    for name, base_path in paths.items():
        for slot in sorted(owned[name].keys() | desired[name].keys(), key=int):
            previous, proposed = owned[name].get(slot), desired[name].get(slot)
            if previous == proposed:
                continue
            path = [*base_path, slot]
            if previous is not None:
                commands.append({"op": "delete", "path": path})
            if proposed is not None:
                for key, value in proposed.items():
                    _set_commands(commands, [*path, key], value)
    return tuple(commands)


def _set_commands(commands, path, value):
    if isinstance(value, dict) and value:
        for key, leaf in value.items():
            _set_commands(commands, [*path, key], leaf)
        return
    if isinstance(value, list):
        for item in value:
            commands.append({"op": "set", "path": path, "value": item})
        return
    command = {"op": "set", "path": path}
    if value != {}:
        command["value"] = value
    commands.append(command)
