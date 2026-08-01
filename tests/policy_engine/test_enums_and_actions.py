"""
Unit tests for policy_engine/enums.py and policy_engine/actions.py.
"""

from __future__ import annotations

import pytest

import policy_engine.enums as enums_module
from policy_engine.actions import ACTION_PRIORITY, PolicyAction
from policy_engine.enums import BaseStringEnum




class DummyEnum(BaseStringEnum):
    ALPHA = "ALPHA"
    BETA = "BETA"


def test_base_string_enum_values():
    assert DummyEnum.values() == ["ALPHA", "BETA"]


def test_base_string_enum_has_value():
    assert DummyEnum.has_value("ALPHA") is True
    assert DummyEnum.has_value("GAMMA") is False
    assert DummyEnum.has_value(123) is False


def test_base_string_enum_from_string():
    assert DummyEnum.from_string("alpha") == DummyEnum.ALPHA
    assert DummyEnum.from_string("BETA") == DummyEnum.BETA

    with pytest.raises(ValueError, match="Invalid DummyEnum value"):
        DummyEnum.from_string("UNKNOWN")


def test_enums_module_getattr_reexports():
    assert getattr(enums_module, "PolicyAction") == PolicyAction
    assert getattr(enums_module, "ACTION_PRIORITY") == ACTION_PRIORITY

    with pytest.raises(AttributeError, match="has no attribute 'NON_EXISTENT'"):
        _ = getattr(enums_module, "NON_EXISTENT")


def test_policy_action_enum_values():
    assert PolicyAction.ALLOW.value == "ALLOW"
    assert PolicyAction.WARN.value == "WARN"
    assert PolicyAction.SANITIZE.value == "SANITIZE"
    assert PolicyAction.BLOCK.value == "BLOCK"


def test_action_priority_mapping():
    assert ACTION_PRIORITY[PolicyAction.BLOCK] == 4
    assert ACTION_PRIORITY[PolicyAction.SANITIZE] == 3
    assert ACTION_PRIORITY[PolicyAction.WARN] == 2
    assert ACTION_PRIORITY[PolicyAction.ALLOW] == 1
