from AuthEncoding import AuthEncoding

import pytest
import transaction


LOGIN = "user_abc"
PASSWORD = "Secret#123456"


@pytest.fixture
def legacy_user(functional_portal):
    legacy = AuthEncoding.pw_encrypt(PASSWORD, encoding="SSHA")
    functional_portal.acl_users.source_users.addUser(LOGIN, LOGIN, legacy)
    transaction.commit()
    return legacy


@pytest.fixture
def stored_password(functional_portal):
    def getter():
        transaction.begin()  # see the changes committed by the server
        return functional_portal.acl_users.source_users._user_passwords[LOGIN]

    return getter


def _assert_rehashed(stored_password, legacy):
    stored = stored_password()
    assert stored != legacy
    assert stored.startswith(b"{ARGON2}$argon2id$")


def test_basic_auth_api(legacy_user, stored_password, request_factory):
    session = request_factory(basic_auth=(LOGIN, PASSWORD))

    response = session.get("/")

    assert response.status_code == 200
    _assert_rehashed(stored_password, legacy_user)


def test_basic_auth_classic_get(legacy_user, stored_password, request_factory):
    session = request_factory(basic_auth=(LOGIN, PASSWORD), api=False)
    session.headers["Accept"] = "text/html"

    response = session.get("/")

    assert response.status_code == 200
    assert "confirm-action" not in response.url
    _assert_rehashed(stored_password, legacy_user)


def test_rest_api_login(legacy_user, stored_password, request_factory):
    session = request_factory()

    response = session.post("/@login", json={"login": LOGIN, "password": PASSWORD})

    assert response.status_code == 200
    assert "token" in response.json()
    _assert_rehashed(stored_password, legacy_user)


def test_classic_login_form(legacy_user, stored_password, request_factory):
    session = request_factory(api=False)
    session.headers["Accept"] = "text/html"

    # sets the test cookie the form checks for ("Cookies are not enabled")
    session.get("/login")
    # anonymous users get no CSRF token (_authenticator) in the login form
    response = session.post(
        "/login",
        data={
            "__ac_name": LOGIN,
            "__ac_password": PASSWORD,
            "buttons.login": "Log in",
        },
    )

    assert response.status_code == 200
    assert "__ac" in session.cookies
    _assert_rehashed(stored_password, legacy_user)


def test_failed_login_keeps_hash(legacy_user, stored_password, request_factory):
    session = request_factory()

    response = session.post("/@login", json={"login": LOGIN, "password": "wrong"})

    assert response.status_code == 401
    assert stored_password() == legacy_user
