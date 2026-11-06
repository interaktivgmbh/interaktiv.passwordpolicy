from AuthEncoding import AuthEncoding
from interaktiv.passwordpolicy.plugins.user import UserManager

import pytest


class TestUserManager:
    @pytest.fixture(autouse=True)
    def _setup(self, portal):
        self.plugin = portal.acl_users.source_users

    def test_source_users_is_interaktiv_user_manager(self):
        assert isinstance(self.plugin, UserManager)

    def test_addUser_hashes_password_with_argon2(self):
        self.plugin.addUser("user_abc", "user_abc", "Secret#123456")

        stored = self.plugin._user_passwords["user_abc"]
        assert stored.startswith(b"{ARGON2}$argon2id$")
        assert AuthEncoding.pw_validate(stored, b"Secret#123456")

    def test_addUser_keeps_encrypted_password(self):
        encrypted = AuthEncoding.pw_encrypt("Secret#123456", encoding="SSHA")

        self.plugin.addUser("user_abc", "user_abc", encrypted)

        assert self.plugin._user_passwords["user_abc"] == encrypted

    def test_addUser_duplicate_user_id(self):
        self.plugin.addUser("user_abc", "user_abc", "Secret#123456")

        with pytest.raises(KeyError):
            self.plugin.addUser("user_abc", "other_login", "Secret#123456")

    def test_doChangeUser_hashes_password_with_argon2(self):
        self.plugin.addUser("user_abc", "user_abc", "Secret#123456")

        self.plugin.doChangeUser("user_abc", "Changed#123456")

        stored = self.plugin._user_passwords["user_abc"]
        assert stored.startswith(b"{ARGON2}$argon2id$")
        assert AuthEncoding.pw_validate(stored, b"Changed#123456")

    def test_doChangeUser_unknown_user(self):
        with pytest.raises(RuntimeError):
            self.plugin.doChangeUser("unknown", "Changed#123456")

    def test_authenticate(self):
        self.plugin.addUser("user_abc", "user_abc", "Secret#123456")

        creds = {"login": "user_abc", "password": "Secret#123456"}
        assert self.plugin.authenticateCredentials(creds) == ("user_abc", "user_abc")

        creds = {"login": "user_abc", "password": "wrong"}
        assert self.plugin.authenticateCredentials(creds) is None

    def test_authenticate_legacy_ssha_hash(self):
        legacy = AuthEncoding.pw_encrypt("Secret#123456", encoding="SSHA")
        self.plugin.addUser("user_abc", "user_abc", legacy)

        creds = {"login": "user_abc", "password": "Secret#123456"}
        assert self.plugin.authenticateCredentials(creds) == ("user_abc", "user_abc")
