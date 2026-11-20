from interaktiv.passwordpolicy import hashing
from interaktiv.passwordpolicy.plugins import user

import pytest


PASSWORD = "Secret#123456"


def test_verify_dummy_does_not_raise():
    hashing.verify_dummy(PASSWORD)


def test_dummy_hash_uses_profile():
    assert b"$m=19456,t=2,p=1$" in hashing._dummy_hash("owasp-19m")


class TestDummyHashOnLogin:
    @pytest.fixture(autouse=True)
    def _setup(self, portal, monkeypatch):
        self.plugin = portal.acl_users.source_users
        self.plugin.addUser("user_abc", "user_abc", PASSWORD)
        self.calls = []
        monkeypatch.setattr(user, "verify_dummy", self.calls.append)

    def _login(self, login, password="wrong"):
        return self.plugin.authenticateCredentials({
            "login": login,
            "password": password,
        })

    def test_unknown_login_verifies_dummy(self):
        assert self._login("nobody") is None
        assert self.calls == ["wrong"]

    def test_wrong_password_skips_dummy(self):
        assert self._login("user_abc") is None
        assert self.calls == []

    def test_correct_password_skips_dummy(self):
        assert self._login("user_abc", PASSWORD) == ("user_abc", "user_abc")
        assert self.calls == []

    def test_missing_password_skips_dummy(self):
        assert self.plugin.authenticateCredentials({"login": "nobody"}) is None
        assert self.calls == []
