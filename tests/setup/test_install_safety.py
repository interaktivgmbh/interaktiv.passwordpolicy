from Acquisition import aq_base
from AuthEncoding import AuthEncoding
from interaktiv.passwordpolicy import setuphandlers
from interaktiv.passwordpolicy.plugins.user import UserManager
from plone import api
from Products.PlonePAS.plugins.user import UserManager as PloneUserManager
from Products.PluggableAuthService.interfaces.plugins import IValidationPlugin

import pytest


PASSWORD = "Secret#123456"


class CustomUserManager(PloneUserManager):
    pass


def _plugin_state(pas):
    return {
        info["id"]: [p[0] for p in pas.plugins.listPlugins(info["interface"])]
        for info in pas.plugins.listPluginTypeInfo()
    }


def _login(pas, login, password=PASSWORD):
    return pas.source_users.authenticateCredentials({
        "login": login,
        "password": password,
    })


@pytest.fixture
def pas(portal):
    return portal.acl_users


@pytest.fixture
def plone_site(pas):
    setuphandlers.uninstall(None)
    assert type(aq_base(pas.source_users)) is PloneUserManager
    return pas


class TestInstall:
    def test_source_users_replaced_with_identical_state(self, plone_site):
        state = dict(aq_base(plone_site.source_users).__dict__)

        setuphandlers.post_install(None)

        after = aq_base(plone_site.source_users)
        assert type(after) is UserManager
        assert after.__dict__ == state
        assert after._user_passwords is state["_user_passwords"]

    def test_plugin_activation_and_order_kept(self, plone_site):
        state = _plugin_state(plone_site)

        setuphandlers.post_install(None)

        expected = dict(state)
        expected["IValidationPlugin"] = ["interaktiv_password_policy"]
        assert _plugin_state(plone_site) == expected

    def test_existing_users_keep_working(self, plone_site):
        api.user.create(email="a@example.com", username="user_abc", password=PASSWORD)
        legacy = plone_site.source_users._user_passwords["user_abc"]
        assert legacy.startswith(b"{SSHA}")

        setuphandlers.post_install(None)

        assert plone_site.source_users._user_passwords["user_abc"] == legacy
        assert _login(plone_site, "user_abc") == ("user_abc", "user_abc")

    def test_install_idempotent(self, pas):
        state = _plugin_state(pas)
        plugin = aq_base(pas.source_users)

        setuphandlers.post_install(None)

        assert _plugin_state(pas) == state
        assert aq_base(pas.source_users) is plugin

    def test_abort_rolls_back(self, plone_site):
        import transaction

        savepoint = transaction.savepoint()
        setuphandlers.post_install(None)
        savepoint.rollback()

        assert type(aq_base(plone_site.source_users)) is PloneUserManager

    def test_custom_user_manager_untouched(self, plone_site):
        plone_site.manage_delObjects(["source_users"])
        plone_site._setObject("source_users", CustomUserManager("source_users"))

        setuphandlers.post_install(None)

        assert type(aq_base(plone_site.source_users)) is CustomUserManager

    def test_missing_user_manager(self, plone_site):
        plone_site.manage_delObjects(["source_users"])

        setuphandlers.post_install(None)

        assert "source_users" not in plone_site.objectIds()


class TestUninstall:
    def test_source_users_replaced_back_with_identical_state(self, pas):
        api.user.create(email="a@example.com", username="user_abc", password=PASSWORD)
        state = dict(aq_base(pas.source_users).__dict__)

        setuphandlers.uninstall(None)

        after = aq_base(pas.source_users)
        assert type(after) is PloneUserManager
        assert after.__dict__ == state
        assert after._user_passwords is state["_user_passwords"]

    def test_plugin_activation_and_order_restored(self, plone_site):
        state = _plugin_state(plone_site)

        setuphandlers.post_install(None)
        setuphandlers.uninstall(None)

        assert _plugin_state(plone_site) == state

    def test_argon2_users_keep_working(self, pas):
        api.user.create(email="a@example.com", username="user_abc", password=PASSWORD)
        assert pas.source_users._user_passwords["user_abc"].startswith(b"{ARGON2}")

        setuphandlers.uninstall(None)

        assert _login(pas, "user_abc") == ("user_abc", "user_abc")

    def test_default_policy_stays_inactive_if_it_was(self, plone_site):
        plone_site.plugins.deactivatePlugin(IValidationPlugin, "password_policy")

        setuphandlers.post_install(None)
        setuphandlers.uninstall(None)

        assert _plugin_state(plone_site)["IValidationPlugin"] == []

    def test_uninstall_twice(self, plone_site):
        state = _plugin_state(plone_site)

        setuphandlers.uninstall(None)

        assert _plugin_state(plone_site) == state

    def test_warns_about_argon2_hashes(self, pas, caplog):
        api.user.create(email="a@example.com", username="user_abc", password=PASSWORD)

        setuphandlers.uninstall(None)

        assert "1 user(s) have Argon2id password hashes" in caplog.text

    def test_legacy_str_passwords(self, pas):
        pas.source_users._user_passwords["old"] = AuthEncoding.pw_encrypt(
            PASSWORD, encoding="SSHA"
        ).decode()
        pas.source_users._login_to_userid["old"] = "old"
        pas.source_users._userid_to_login["old"] = "old"

        setuphandlers.uninstall(None)

        assert _login(pas, "old") == ("old", "old")
