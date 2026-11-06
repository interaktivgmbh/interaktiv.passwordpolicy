from interaktiv.passwordpolicy import PACKAGE_NAME

import pytest


class TestSetupUninstall:
    @pytest.fixture(autouse=True)
    def uninstalled(self, installer):
        installer.uninstall_product(PACKAGE_NAME)

    def test_addon_uninstalled(self, installer):
        assert installer.is_product_installed(PACKAGE_NAME) is False

    def test_browserlayer_not_registered(self, browser_layers):
        from interaktiv.passwordpolicy.interfaces import IBrowserLayer

        assert IBrowserLayer not in browser_layers

    def test_default_password_policy_restored(self, portal):
        from Products.PluggableAuthService.interfaces.plugins import IValidationPlugin

        pas = portal.acl_users
        assert "interaktiv_password_policy" not in pas.objectIds()

        active = [p[0] for p in pas.plugins.listPlugins(IValidationPlugin)]
        assert active == ["password_policy"]

    def test_default_user_manager_restored(self, portal):
        from Acquisition import aq_base
        from Products.PlonePAS.plugins.user import UserManager

        assert type(aq_base(portal.acl_users["source_users"])) is UserManager
