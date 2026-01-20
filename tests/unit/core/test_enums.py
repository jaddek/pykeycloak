"""
Unit tests for the enums module.
"""

import pytest
from pykeycloak.core.enums import (
    AuthFlowsEnum,
    PermissionTypeEnum,
    DecisionStrategyEnum,
    LogicEnum
)


class TestAuthFlowsEnum:
    """Test cases for the AuthFlowsEnum class."""

    def test_authorization_code_flow_value(self):
        """Test the value of AuthorizationCodeFlow enum member."""
        assert AuthFlowsEnum.AuthorizationCodeFlow.value == "AuthorizationCodeFlow"

    def test_implicit_flow_value(self):
        """Test the value of ImplicitFlow enum member."""
        assert AuthFlowsEnum.ImplicitFlow.value == "ImplicitFlow"

    def test_resource_owner_password_credentials_flow_value(self):
        """Test the value of ResourceOwnerPasswordCredentialsFlow enum member."""
        assert AuthFlowsEnum.ResourceOwnerPasswordCredentialsFlow.value == "ResourceOwnerPasswordCredentialsFlow"

    def test_token_exchange_flow_value(self):
        """Test the value of TokenExchangeFlow enum member."""
        assert AuthFlowsEnum.TokenExchangeFlow.value == "TokenExchangeFlow"

    def test_client_credentials_flow_value(self):
        """Test the value of ClientCredentialsFlow enum member."""
        assert AuthFlowsEnum.ClientCredentialsFlow.value == "ClientCredentialsFlow"

    def test_device_flow_value(self):
        """Test the value of DeviceFlow enum member."""
        assert AuthFlowsEnum.DeviceFlow.value == "DeviceFlow"

    def test_ciba_flow_value(self):
        """Test the value of CibaFlow enum member."""
        assert AuthFlowsEnum.CibaFlow.value == "CibaFlow"

    def test_all_auth_flows_have_correct_values(self):
        """Test that all AuthFlowsEnum members have correct string values."""
        expected_values = [
            "AuthorizationCodeFlow",
            "ImplicitFlow",
            "ResourceOwnerPasswordCredentialsFlow",
            "TokenExchangeFlow",
            "ClientCredentialsFlow",
            "DeviceFlow",
            "CibaFlow"
        ]
        
        actual_values = [flow.value for flow in AuthFlowsEnum]
        assert sorted(actual_values) == sorted(expected_values)


class TestPermissionTypeEnum:
    """Test cases for the PermissionTypeEnum class."""

    def test_resource_permission_type_value(self):
        """Test the value of RESOURCE enum member."""
        assert PermissionTypeEnum.RESOURCE.value == "resource"

    def test_scope_permission_type_value(self):
        """Test the value of SCOPE enum member."""
        assert PermissionTypeEnum.SCOPE.value == "scope"

    def test_all_permission_types_have_correct_values(self):
        """Test that all PermissionTypeEnum members have correct string values."""
        expected_values = ["resource", "scope"]
        actual_values = [perm_type.value for perm_type in PermissionTypeEnum]
        assert sorted(actual_values) == sorted(expected_values)


class TestDecisionStrategyEnum:
    """Test cases for the DecisionStrategyEnum class."""

    def test_affirmative_decision_strategy_value(self):
        """Test the value of AFFIRMATIVE enum member."""
        assert DecisionStrategyEnum.AFFIRMATIVE.value == "AFFIRMATIVE"

    def test_unanimous_decision_strategy_value(self):
        """Test the value of UNANIMOUS enum member."""
        assert DecisionStrategyEnum.UNANIMOUS.value == "UNANIMOUS"

    def test_consensus_decision_strategy_value(self):
        """Test the value of CONSENSUS enum member."""
        assert DecisionStrategyEnum.CONSENSUS.value == "CONSENSUS"

    def test_all_decision_strategies_have_correct_values(self):
        """Test that all DecisionStrategyEnum members have correct string values."""
        expected_values = ["AFFIRMATIVE", "UNANIMOUS", "CONSENSUS"]
        actual_values = [strategy.value for strategy in DecisionStrategyEnum]
        assert sorted(actual_values) == sorted(expected_values)


class TestLogicEnum:
    """Test cases for the LogicEnum class."""

    def test_positive_logic_value(self):
        """Test the value of POSITIVE enum member."""
        assert LogicEnum.POSITIVE.value == "POSITIVE"

    def test_negative_logic_value(self):
        """Test the value of NEGATIVE enum member."""
        assert LogicEnum.NEGATIVE.value == "NEGATIVE"

    def test_all_logic_values_have_correct_values(self):
        """Test that all LogicEnum members have correct string values."""
        expected_values = ["POSITIVE", "NEGATIVE"]
        actual_values = [logic.value for logic in LogicEnum]
        assert sorted(actual_values) == sorted(expected_values)


class TestStrEnumInheritance:
    """Test that enums properly inherit from StrEnum."""

    def test_auth_flows_enum_is_str_enum(self):
        """Test that AuthFlowsEnum can be compared to strings."""
        assert AuthFlowsEnum.AuthorizationCodeFlow == "AuthorizationCodeFlow"
        assert str(AuthFlowsEnum.ImplicitFlow) == "ImplicitFlow"

    def test_permission_type_enum_is_str_enum(self):
        """Test that PermissionTypeEnum can be compared to strings."""
        assert PermissionTypeEnum.RESOURCE == "resource"
        assert str(PermissionTypeEnum.SCOPE) == "scope"

    def test_decision_strategy_enum_is_str_enum(self):
        """Test that DecisionStrategyEnum can be compared to strings."""
        assert DecisionStrategyEnum.AFFIRMATIVE == "AFFIRMATIVE"
        assert str(DecisionStrategyEnum.UNANIMOUS) == "UNANIMOUS"

    def test_logic_enum_is_str_enum(self):
        """Test that LogicEnum can be compared to strings."""
        assert LogicEnum.POSITIVE == "POSITIVE"
        assert str(LogicEnum.NEGATIVE) == "NEGATIVE"