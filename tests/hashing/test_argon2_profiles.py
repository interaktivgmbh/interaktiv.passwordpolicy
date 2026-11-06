from argon2 import extract_parameters
from AuthEncoding import AuthEncoding
from interaktiv.passwordpolicy import hashing
from interaktiv.passwordpolicy.hashing import DEFAULT_PROFILE
from interaktiv.passwordpolicy.hashing import get_profile
from interaktiv.passwordpolicy.hashing import PROFILES
from plone import api

import pytest


PASSWORD = "Secret#123456"
RECORD = "interaktiv.passwordpolicy.argon2_profile"


def _parameters(hashed: bytes):
    return extract_parameters(hashed[len(b"{ARGON2}") :].decode())


def test_scheme_registered():
    assert "ARGON2" in AuthEncoding.listSchemes()


def test_default_profile_without_site():
    assert get_profile() == DEFAULT_PROFILE

    params = _parameters(hashing.hash_password(PASSWORD))
    assert params == PROFILES[DEFAULT_PROFILE]


def test_unknown_profile_falls_back_to_default(monkeypatch):
    from interaktiv.passwordpolicy import utils

    monkeypatch.setattr(
        utils, "queryUtility", lambda iface: {RECORD: "removed-profile"}
    )

    assert get_profile() == DEFAULT_PROFILE


class TestConfiguredProfile:
    @pytest.fixture(autouse=True)
    def _setup(self, portal):
        self.portal = portal

    def test_default_profile(self):
        assert api.portal.get_registry_record(RECORD) == DEFAULT_PROFILE
        assert get_profile() == DEFAULT_PROFILE

    @pytest.mark.parametrize("profile", sorted(PROFILES))
    def test_hash_password_uses_configured_profile(self, profile):
        api.portal.set_registry_record(RECORD, profile)

        hashed = hashing.hash_password(PASSWORD)

        assert _parameters(hashed) == PROFILES[profile]
        assert AuthEncoding.pw_validate(hashed, PASSWORD)

    def test_needs_rehash_uses_configured_profile(self):
        hashed = hashing.hash_password(PASSWORD)
        assert not hashing.needs_rehash(hashed)

        api.portal.set_registry_record(RECORD, "owasp-7m")

        assert hashing.needs_rehash(hashed)

    def test_existing_hashes_survive_profile_change(self):
        hashed = hashing.hash_password(PASSWORD)

        api.portal.set_registry_record(RECORD, "owasp-7m")

        assert _parameters(hashed) == PROFILES[DEFAULT_PROFILE]
        assert AuthEncoding.pw_validate(hashed, PASSWORD)
