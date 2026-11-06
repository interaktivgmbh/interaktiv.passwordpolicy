from interaktiv.passwordpolicy.config import MIN_PASSWORD_LENGTH
from interaktiv.passwordpolicy.plugins.passwordpolicy import PASSWORD_REQUIREMENTS
from interaktiv.passwordpolicy.plugins.passwordpolicy import password_too_short
from interaktiv.passwordpolicy.plugins.passwordpolicy import PasswordPolicyPlugin
from plone import api
from zope.globalrequest import getRequest
from zope.globalrequest import setRequest
from zope.i18n import translate

import json
import pytest


REQUIREMENTS = [requirement.message for requirement in PASSWORD_REQUIREMENTS]
LOWER, UPPER, NUMBER, SPECIAL = range(4)
SETTINGS = {
    LOWER: "require_lowercase",
    UPPER: "require_uppercase",
    NUMBER: "require_number",
    SPECIAL: "require_special",
}


def _set(setting, value):
    api.portal.set_registry_record(f"interaktiv.passwordpolicy.{setting}", value)


class TestPasswordPolicyPlugin:
    @pytest.fixture(autouse=True)
    def _setup(self, portal):
        self.portal = portal
        self.request = portal.REQUEST
        setRequest(self.request)
        self.plugin = PasswordPolicyPlugin("password_policy")
        yield
        setRequest(None)

    def _translate(self, msg):
        return translate(msg, context=getRequest())

    def test_validate_password__no_password(self):
        assert self.plugin._validate_password("") == []

    def test_validate_password__too_short(self):
        result = self.plugin._validate_password("test")

        assert len(result) == 1
        assert result[0]["error"] == self._translate(
            password_too_short(MIN_PASSWORD_LENGTH)
        )

    def test_validate_password__uses_configured_min_length(self):
        api.portal.set_registry_record(
            "interaktiv.passwordpolicy.min_password_length", 20
        )

        too_short = self.plugin._validate_password("SuperSecure123@")
        long_enough = self.plugin._validate_password("SuperSecurePassword123@")

        assert [err["error"] for err in too_short] == [
            self._translate(password_too_short(20))
        ]
        assert long_enough == []

    def test_validate_password__lower_min_length(self):
        api.portal.set_registry_record(
            "interaktiv.passwordpolicy.min_password_length", 4
        )

        assert self.plugin._validate_password("aB1#") == []

    @pytest.mark.parametrize(
        "password,failures",
        [
            ("testpassword", (UPPER, NUMBER, SPECIAL)),
            ("TESTPASSWORD", (LOWER, NUMBER, SPECIAL)),
            ("testpassword1", (UPPER, SPECIAL)),
            ("TESTPASSWORD1", (LOWER, SPECIAL)),
            ("testpassword1#", (UPPER,)),
            ("TESTPASSWORD1#", (LOWER,)),
            ("123456789#", (LOWER, UPPER)),
            ("##########", (LOWER, UPPER, NUMBER)),
            ("SuperSecurePassword123@", ()),
            ("sh389ASKJ!?fa@45bV#", ()),
        ],
    )
    def test_validate_password(self, password, failures):
        result = self.plugin._validate_password(password)

        errors = [res["error"] for res in result]
        assert len(errors) == len(failures)
        for failure in failures:
            assert self._translate(REQUIREMENTS[failure]) in errors

    @pytest.mark.parametrize(
        "password,failures",
        [
            ("ÄÖÜÄÖÜ12#", (LOWER,)),
            ("äöüäöü12#", (UPPER,)),
            ("Straße12#", ()),
            ("Password12 ", ()),
            ("Password12€", ()),
            ("Password12§", ()),
            ("Password12_", ()),
            ("Pässwörd123", (SPECIAL,)),
        ],
    )
    def test_validate_password__unicode(self, password, failures):
        result = self.plugin._validate_password(password)

        errors = [res["error"] for res in result]
        assert errors == [self._translate(REQUIREMENTS[f]) for f in failures]

    @pytest.mark.parametrize("disabled", [LOWER, UPPER, NUMBER, SPECIAL])
    def test_validate_password__requirement_disabled(self, disabled):
        _set(SETTINGS[disabled], False)

        # between them, these passwords violate every requirement
        for password in ("##########", "abcdefghij", "ABCDEFGHIJ", "1234567890"):
            errors = [res["error"] for res in self.plugin._validate_password(password)]
            assert self._translate(REQUIREMENTS[disabled]) not in errors

    def test_validate_password__all_requirements_disabled(self):
        for setting in SETTINGS.values():
            _set(setting, False)

        assert self.plugin._validate_password("aaaaaaaaaa") == []

    def test_validate_password__length_still_checked_without_requirements(self):
        for setting in SETTINGS.values():
            _set(setting, False)

        result = self.plugin._validate_password("aaa")

        assert [res["error"] for res in result] == [
            self._translate(password_too_short(MIN_PASSWORD_LENGTH))
        ]

    def test_validateUserInfo__no_set_info(self):
        assert self.plugin.validateUserInfo(None, "test_user", {}) == []

    def test_validateUserInfo__generated_password_skips_validation(self):
        password = self.portal.portal_registration.generatePassword()

        result = self.plugin.validateUserInfo(
            user=None, set_id="test_user", set_info={"password": password}
        )

        assert result == []

    def test_validateUserInfo__generated_looking_password_from_client(self):
        password = self.portal.portal_registration.generatePassword()
        self.request["BODY"] = json.dumps({"new_password": password})

        result = self.plugin.validateUserInfo(
            user=None, set_id="test_user", set_info={"password": password}
        )

        assert result != []

    def test_validateUserInfo__sendPasswordReset_flag_does_not_bypass(self):
        self.request["BODY"] = json.dumps({"sendPasswordReset": True})

        result = self.plugin.validateUserInfo(
            user=None, set_id="test_user", set_info={"password": "weak"}
        )

        assert result != []

    def test_validateUserInfo__normal_request_validates_password(self):
        self.request["BODY"] = json.dumps({"some_other_field": "value"})

        result = self.plugin.validateUserInfo(
            user=None, set_id="test_user", set_info={"password": "weak"}
        )

        assert len(result) > 0
