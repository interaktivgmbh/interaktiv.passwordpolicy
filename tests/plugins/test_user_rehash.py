from AuthEncoding import AuthEncoding
from interaktiv.passwordpolicy.hashing import ARGON2
from interaktiv.passwordpolicy.hashing import needs_rehash
from plone import api

import pytest


PASSWORD = "Secret#123456"
PROFILE_RECORD = "interaktiv.passwordpolicy.argon2_profile"


@pytest.mark.parametrize("scheme", ["SSHA", "SHA256", "SHA"])
def test_needs_rehash_legacy_schemes(scheme):
    assert needs_rehash(AuthEncoding.pw_encrypt(PASSWORD, encoding=scheme))


def test_needs_rehash_unprefixed_legacy_hash():
    assert needs_rehash("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")


def test_needs_rehash_current_argon2():
    assert not needs_rehash(AuthEncoding.pw_encrypt(PASSWORD, encoding=ARGON2))


def test_needs_rehash_str_reference():
    hashed = AuthEncoding.pw_encrypt(PASSWORD, encoding=ARGON2).decode()
    assert not needs_rehash(hashed)


class TestRehashOnLogin:
    @pytest.fixture(autouse=True)
    def _setup(self, portal):
        self.plugin = portal.acl_users.source_users

    def _add_user(self, stored_password):
        self.plugin.addUser("user_abc", "user_abc", stored_password)

    def _login(self, password=PASSWORD):
        return self.plugin.authenticateCredentials({
            "login": "user_abc",
            "password": password,
        })

    @property
    def _stored(self):
        return self.plugin._user_passwords["user_abc"]

    @pytest.mark.parametrize("scheme", ["SSHA", "SHA256"])
    def test_legacy_hash_rehashed(self, scheme):
        self._add_user(AuthEncoding.pw_encrypt(PASSWORD, encoding=scheme))

        assert self._login() == ("user_abc", "user_abc")

        assert self._stored.startswith(b"{ARGON2}$argon2id$")
        assert not needs_rehash(self._stored)
        assert self._login() == ("user_abc", "user_abc")

    def test_wrong_password_does_not_rehash(self):
        legacy = AuthEncoding.pw_encrypt(PASSWORD, encoding="SSHA")
        self._add_user(legacy)

        assert self._login("wrong") is None

        assert self._stored == legacy

    def test_current_hash_untouched(self):
        self._add_user(PASSWORD)
        current = self._stored

        self._login()

        assert self._stored == current

    def test_rehash_after_profile_change(self):
        self._add_user(PASSWORD)
        old = self._stored

        api.portal.set_registry_record(PROFILE_RECORD, "owasp-19m")
        self._login()

        assert self._stored != old
        assert b"$m=19456,t=2,p=1$" in self._stored
        assert self._login() == ("user_abc", "user_abc")

    def test_read_only_database_skips_rehash(self, monkeypatch):
        legacy = AuthEncoding.pw_encrypt(PASSWORD, encoding="SSHA")
        self._add_user(legacy)
        monkeypatch.setattr(self.plugin._p_jar, "isReadOnly", lambda: True)

        assert self._login() == ("user_abc", "user_abc")

        assert self._stored == legacy
