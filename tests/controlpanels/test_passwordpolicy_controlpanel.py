from interaktiv.passwordpolicy.config import MIN_PASSWORD_LENGTH
from interaktiv.passwordpolicy.controlpanels.passwordpolicy_settings import (
    IPasswordPolicySettings,
)
from plone import api

import pytest
import transaction


CONFIGLET_ID = "passwordpolicy-controlpanel"
RECORD = "interaktiv.passwordpolicy.min_password_length"


class TestPasswordPolicyControlpanel:
    def test_controlpanel_view(self, portal, http_request):
        view = api.content.get_view(CONFIGLET_ID, context=portal, request=http_request)
        assert view.form.schema is IPasswordPolicySettings

    def test_configlet_registered(self, controlpanel_actions):
        assert CONFIGLET_ID in controlpanel_actions

    def test_registry_record_default(self, portal):
        assert api.portal.get_registry_record(RECORD) == MIN_PASSWORD_LENGTH


class TestPasswordPolicyControlpanelUninstalled:
    @pytest.fixture(autouse=True)
    def uninstalled(self, installer):
        installer.uninstall_product("interaktiv.passwordpolicy")

    def test_configlet_removed(self, controlpanel_actions):
        assert CONFIGLET_ID not in controlpanel_actions

    def test_registry_record_removed(self, portal):
        assert api.portal.get_registry_record(RECORD, default=None) is None


class TestPasswordPolicyControlpanelRestAPI:
    URL = f"/@controlpanels/{CONFIGLET_ID}"

    def test_get(self, manager_request):
        response = manager_request.get(self.URL)

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["min_password_length"] == MIN_PASSWORD_LENGTH
        assert "min_password_length" in data["schema"]["properties"]

    def test_listed(self, manager_request):
        response = manager_request.get("/@controlpanels")

        ids = [panel["@id"].split("/")[-1] for panel in response.json()]
        assert CONFIGLET_ID in ids

    def test_patch(self, manager_request, functional_portal):
        response = manager_request.patch(self.URL, json={"min_password_length": 16})

        assert response.status_code == 204
        transaction.begin()
        assert api.portal.get_registry_record(RECORD) == 16

    def test_patch_rejects_invalid_value(self, manager_request):
        response = manager_request.patch(self.URL, json={"min_password_length": 0})

        assert response.status_code == 400

    def test_anonymous_forbidden(self, anon_request):
        response = anon_request.get(self.URL)

        assert response.status_code == 401

    def test_get_requirements(self, manager_request):
        data = manager_request.get(self.URL).json()

        for setting in (
            "require_lowercase",
            "require_uppercase",
            "require_number",
            "require_special",
        ):
            assert data["data"][setting] is True
            assert data["schema"]["properties"][setting]["type"] == "boolean"

    def test_patch_requirement(self, manager_request, functional_portal):
        response = manager_request.patch(self.URL, json={"require_special": False})

        assert response.status_code == 204
        transaction.begin()
        assert (
            api.portal.get_registry_record("interaktiv.passwordpolicy.require_special")
            is False
        )

    def test_get_argon2_profile(self, manager_request):
        response = manager_request.get(self.URL)

        data = response.json()
        assert data["data"]["argon2_profile"]["token"] == "rfc9106-low-memory"
        assert "argon2_profile" in data["schema"]["properties"]

    def test_patch_argon2_profile(self, manager_request, functional_portal):
        response = manager_request.patch(self.URL, json={"argon2_profile": "owasp-19m"})

        assert response.status_code == 204
        transaction.begin()
        assert (
            api.portal.get_registry_record("interaktiv.passwordpolicy.argon2_profile")
            == "owasp-19m"
        )

    def test_patch_rejects_unknown_argon2_profile(self, manager_request):
        response = manager_request.patch(self.URL, json={"argon2_profile": "md5"})

        assert response.status_code == 400


class TestPasswordPolicyControlpanelNotInstalled:
    @pytest.fixture(autouse=True)
    def uninstalled(self, functional_portal):
        from plone.base.utils import get_installer

        get_installer(functional_portal).uninstall_product("interaktiv.passwordpolicy")
        transaction.commit()

    def test_rest_api_not_found(self, manager_request):
        response = manager_request.get(f"/@controlpanels/{CONFIGLET_ID}")

        assert response.status_code == 404

    def test_classic_view_not_found(self, request_factory):
        session = request_factory(role="Manager", api=False)

        response = session.get(f"/@@{CONFIGLET_ID}")

        assert response.status_code == 404
