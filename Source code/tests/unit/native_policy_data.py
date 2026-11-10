"""Invented NetSecurity-shaped records; not claimed as captured Windows fixtures."""

from typing import Any


def native_rule_data() -> dict[str, Any]:
    return {
        "rule": {
            "Name": ["synthetic-stable-rule"],
            "DisplayName": ["Invented Ω policy"],
            "Enabled": ["True"],
            "Action": ["Block"],
            "Direction": ["Outbound"],
            "Profile": ["Private"],
            "PolicyStoreSource": ["PersistentStore"],
            "PolicyStoreSourceType": ["Local"],
            "EdgeTraversalPolicy": ["Block"],
            "LooseSourceMapping": ["False"],
            "LocalOnlyMapping": ["False"],
            "Owner": [""],
        },
        "filters": {
            "application": {"Program": [r"C:\Training\例 Ω.exe"], "Package": ["Any"]},
            "address": {"LocalAddress": ["Any"], "RemoteAddress": ["192.0.2.10/32"]},
            "port": {
                "Protocol": ["TCP"],
                "LocalPort": ["Any"],
                "RemotePort": ["443"],
                "IcmpType": ["Any"],
                "DynamicTarget": ["Any"],
            },
            "service": {"Service": ["Any"]},
            "interface": {"InterfaceAlias": ["Any"]},
            "interface_type": {"InterfaceType": ["Any"]},
            "security": {
                "Authentication": ["NotRequired"],
                "Encryption": ["NotRequired"],
                "OverrideBlockRules": ["False"],
                "LocalUser": ["Any"],
                "RemoteUser": ["Any"],
                "RemoteMachine": ["Any"],
            },
        },
        "filter_errors": [],
    }
