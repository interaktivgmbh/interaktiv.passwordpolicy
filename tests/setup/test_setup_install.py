from interaktiv.passwordpolicy import PACKAGE_NAME

import pytest


class TestSetupInstall:
    def test_addon_installed(self, installer):
        assert installer.is_product_installed(PACKAGE_NAME) is True

    def test_browserlayer(self, browser_layers):
        from interaktiv.passwordpolicy.interfaces import IBrowserLayer

        assert IBrowserLayer in browser_layers

    def test_latest_version(self, profile_last_version):
        assert profile_last_version(f"{PACKAGE_NAME}:default") == "1000"

    def test_password_policy_on_top_of_default(self, portal):
        from interaktiv.passwordpolicy.plugins.passwordpolicy import (
            PasswordPolicyPlugin,
        )
        from Products.PluggableAuthService.interfaces.plugins import IValidationPlugin

        pas = portal.acl_users
        assert isinstance(pas["interaktiv_password_policy"], PasswordPolicyPlugin)
        assert "password_policy" in pas.objectIds()

        active = [p[0] for p in pas.plugins.listPlugins(IValidationPlugin)]
        assert active == ["interaktiv_password_policy"]

    def test_install_password_policy_idempotent(self, portal):
        from interaktiv.passwordpolicy.setuphandlers import install_password_policy
        from Products.PluggableAuthService.interfaces.plugins import IValidationPlugin

        install_password_policy()

        active = portal.acl_users.plugins.listPlugins(IValidationPlugin)
        assert [p[0] for p in active] == ["interaktiv_password_policy"]

    def test_user_manager_installed(self, portal):
        from interaktiv.passwordpolicy.plugins.user import UserManager

        assert isinstance(portal.acl_users["source_users"], UserManager)

    def test_install_user_manager_keeps_users(self, portal):
        from interaktiv.passwordpolicy.plugins.user import UserManager
        from interaktiv.passwordpolicy.setuphandlers import install_user_manager
        from interaktiv.passwordpolicy.setuphandlers import remove_user_manager
        from plone import api

        remove_user_manager()
        api.user.create(
            email="user_abc@example.com",
            username="user_abc",
            password="Secret#123456",
        )

        install_user_manager()

        assert isinstance(portal.acl_users["source_users"], UserManager)
        assert api.user.get(username="user_abc") is not None


class TestPasswordValidity:
    @pytest.fixture(autouse=True)
    def _setup(self, portal):
        from zope.globalrequest import setRequest

        setRequest(portal.REQUEST)
        self.registration = portal.portal_registration
        yield
        setRequest(None)

    def test_valid_password(self):
        assert self.registration.testPasswordValidity("SuperSecure123@") is None

    def test_min_length_below_default_policy(self):
        from plone import api

        api.portal.set_registry_record(
            "interaktiv.passwordpolicy.min_password_length", 4
        )

        # 7 chars would be rejected by Plone's default policy (min 8)
        assert self.registration.testPasswordValidity("aB1#xyz") is None

    def test_too_short_reports_only_our_message(self):
        from plone import api

        api.portal.set_registry_record(
            "interaktiv.passwordpolicy.min_password_length", 12
        )

        error = self.registration.testPasswordValidity("aB1#")

        assert "12" in error
        assert "8" not in error
