from interaktiv.passwordpolicy.subscribers.login import RESET_COOKIE
from plone import api
from Products.CMFPlone.tests.utils import MockMailHost

import pytest
import transaction


LOGIN = "member_abc"
WEAK = "Secret#123"  # 10 characters, meets the default policy
STRONG = "A much longer Secret#1234"
RECORD = "interaktiv.passwordpolicy.{}"


def _set(name, value):
    api.portal.set_registry_record(RECORD.format(name), value)


@pytest.fixture
def mailhost(functional_portal):
    mailhost = MockMailHost("MailHost")
    functional_portal.MailHost = mailhost
    api.portal.set_registry_record("plone.email_from_address", "site@example.com")
    return mailhost


def _create_member():
    api.user.create(email="member@example.com", username=LOGIN, password=WEAK)
    # the policy got stricter after the password was set
    _set("min_password_length", 15)


@pytest.fixture
def member(functional_portal, mailhost):
    _create_member()
    transaction.commit()


@pytest.fixture
def enforced(member):
    _set("require_change_on_login", True)
    transaction.commit()


@pytest.fixture
def enforced_without_email(enforced):
    api.user.get(username=LOGIN).setMemberProperties({"email": ""})
    transaction.commit()


@pytest.fixture
def enforced_without_mailhost(functional_portal):
    _create_member()
    _set("require_change_on_login", True)
    transaction.commit()


@pytest.fixture
def reset_tool(functional_portal):
    return functional_portal.portal_password_reset


def _rest_login(request_factory, password, handles_token=False):
    headers = {"X-Password-Change": "reset-token"} if handles_token else {}

    return request_factory().post(
        "/@login", json={"login": LOGIN, "password": password}, headers=headers
    )


def _classic_session(request_factory):
    session = request_factory(api=False)
    session.headers["Accept"] = "text/html"
    session.get("/login")  # sets the test cookie the login form checks for
    return session


def _classic_login(request_factory, password):
    session = _classic_session(request_factory)
    response = session.post(
        "/login",
        data={
            "__ac_name": LOGIN,
            "__ac_password": password,
            "buttons.login": "Log in",
        },
    )
    return session, response


def _sent_mails(mailhost):
    transaction.begin()
    return mailhost.messages


def _tokens(reset_tool):
    transaction.begin()
    return [
        token for token, (userid, _) in reset_tool._requests.items() if userid == LOGIN
    ]


def _assert_logged_in(response):
    assert response.status_code == 200
    assert "token" in response.json()


def test_disabled_by_default(member, request_factory, mailhost, reset_tool):
    _assert_logged_in(_rest_login(request_factory, WEAK))
    assert _sent_mails(mailhost) == []
    assert _tokens(reset_tool) == []


def test_compliant_password_logs_in(enforced, request_factory, functional_portal):
    functional_portal.acl_users.source_users.doChangeUser(LOGIN, STRONG)
    transaction.commit()

    _assert_logged_in(_rest_login(request_factory, STRONG))


def test_wrong_password_unchanged(enforced, request_factory, mailhost, reset_tool):
    response = _rest_login(request_factory, "wrong")
    assert response.status_code == 401
    assert response.json()["error"]["type"] == "Invalid credentials"

    _session, response = _classic_login(request_factory, "wrong")
    assert "passwordreset" not in response.url

    assert _sent_mails(mailhost) == []
    assert _tokens(reset_tool) == []


def test_basic_auth_not_affected(enforced, request_factory, mailhost, reset_tool):
    session = request_factory(basic_auth=(LOGIN, WEAK))

    response = session.get(f"/@users/{LOGIN}")

    assert response.status_code == 200
    assert _sent_mails(mailhost) == []
    assert _tokens(reset_tool) == []


class TestClassicUI:
    def test_with_email(self, enforced, request_factory, mailhost):
        session, response = _classic_login(request_factory, WEAK)

        assert response.url.endswith("/login")
        assert "We have sent you an email" in response.text
        assert "Login failed" not in response.text
        assert "__ac" not in session.cookies
        assert len(_sent_mails(mailhost)) == 1

    def test_without_email(
        self, enforced_without_email, request_factory, reset_tool, mailhost
    ):
        session, response = _classic_login(request_factory, WEAK)

        [token] = _tokens(reset_tool)
        assert response.url.endswith(f"/passwordreset/{token}")
        assert "Please set a new password." in response.text
        assert "Login failed" not in response.text
        assert "__ac" not in session.cookies
        assert _sent_mails(mailhost) == []

    def test_without_mail_server(self, enforced_without_mailhost, request_factory):
        session, response = _classic_login(request_factory, WEAK)

        assert response.status_code == 200
        assert "/passwordreset/" in response.url
        assert "__ac" not in session.cookies

    def _modal_login(self, request_factory):
        session = _classic_session(request_factory)
        response = session.post(
            "/login",
            data={
                "__ac_name": LOGIN,
                "__ac_password": WEAK,
                "buttons.login": "Log in",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
            allow_redirects=False,
        )
        return session, response

    def test_login_modal_with_email(self, enforced, request_factory, mailhost):
        session, response = self._modal_login(request_factory)

        assert response.status_code == 200
        assert "alert-danger" not in response.text
        assert RESET_COOKIE not in session.cookies
        assert len(_sent_mails(mailhost)) == 1

        # the reload of the modal
        page = session.get("/")
        assert "/passwordreset/" not in page.url
        assert "We have sent you an email" in page.text

    def test_login_modal(self, enforced_without_email, request_factory, reset_tool):
        session, response = self._modal_login(request_factory)

        [token] = _tokens(reset_tool)
        assert response.status_code == 200
        # the modal's error selectors, otherwise it would not reload
        assert "alert-danger" not in response.text
        assert "portalMessage" not in response.text
        assert session.cookies.get(RESET_COOKIE) == token
        assert "__ac" not in session.cookies

        # the reload of the modal
        page = session.get("/")
        assert page.url.endswith(f"/passwordreset/{token}")
        assert "Please set a new password." in page.text
        assert "Login failed" not in page.text
        assert RESET_COOKIE not in session.cookies

    def test_login_modal_waits_for_page(self, enforced_without_email, request_factory):
        session, _response = self._modal_login(request_factory)

        response = session.get(
            "/favicon.ico", headers={"Accept": "image/*"}, allow_redirects=False
        )

        assert response.status_code != 302
        assert RESET_COOKIE in session.cookies

    def test_reset_cookie_must_be_a_token(self, enforced, request_factory):
        session = _classic_session(request_factory)
        session.cookies.set(RESET_COOKIE, "../../@@overview-controlpanel")

        response = session.get("/", allow_redirects=False)

        assert response.status_code == 200
        expired = response.headers["Set-Cookie"]
        assert f"{RESET_COOKIE}=deleted" in expired or "Max-Age=0" in expired

    def test_reset_and_login(self, enforced, request_factory, reset_tool):
        session, response = _classic_login(request_factory, WEAK)
        [token] = _tokens(reset_tool)

        response = session.post(
            f"/passwordreset/{token}",
            data={
                "userid": LOGIN,
                "password": STRONG,
                "password2": STRONG,
                "form.submitted": "1",
            },
        )

        assert response.status_code == 200
        # plone.autologin_after_password_reset is enabled by default
        assert "__ac" in session.cookies
        assert _tokens(reset_tool) == []

    def test_reset_form_enforces_policy(self, enforced, request_factory, reset_tool):
        session, response = _classic_login(request_factory, WEAK)
        [token] = _tokens(reset_tool)

        response = session.post(
            f"/passwordreset/{token}",
            data={
                "userid": LOGIN,
                "password": "short#1A",
                "password2": "short#1A",
                "form.submitted": "1",
            },
        )

        assert "at least 15 characters" in response.text
        assert _tokens(reset_tool) == [token]


@pytest.fixture
def no_reset_token(monkeypatch):
    from Products.CMFPlone.PasswordResetTool import PasswordResetTool

    monkeypatch.setattr(PasswordResetTool, "requestReset", lambda self, userid: None)


def test_classic_without_reset_token_logs_in(enforced, no_reset_token, request_factory):
    session, response = _classic_login(request_factory, WEAK)

    assert "/passwordreset/" not in response.url
    assert "__ac" in session.cookies


def test_rest_without_reset_token_logs_in(enforced, no_reset_token, request_factory):
    _assert_logged_in(_rest_login(request_factory, WEAK))


class TestRestAPI:
    @pytest.mark.parametrize("handles_token", [False, True])
    def test_with_email(self, enforced, request_factory, mailhost, handles_token):
        response = _rest_login(request_factory, WEAK, handles_token)

        assert response.status_code == 401
        error = response.json()["error"]
        assert error["type"] == "Password change required"
        assert "We have sent you an email" in error["message"]
        assert "reset_token" not in error
        assert "token" not in response.json()
        assert len(_sent_mails(mailhost)) == 1

    def test_without_email_refused_with_token(
        self, enforced_without_email, request_factory, reset_tool, mailhost
    ):
        response = _rest_login(request_factory, WEAK, handles_token=True)

        assert response.status_code == 401
        error = response.json()["error"]
        assert error["type"] == "Password change required"
        assert "Please set a new password." in error["message"]
        assert error["reset_token"] in _tokens(reset_tool)
        assert "token" not in response.json()
        assert _sent_mails(mailhost) == []

    def test_reset_with_token_and_login(self, enforced_without_email, request_factory):
        token = _rest_login(request_factory, WEAK, handles_token=True).json()["error"][
            "reset_token"
        ]

        response = request_factory().post(
            f"/@users/{LOGIN}/reset-password",
            json={"reset_token": token, "new_password": STRONG},
        )
        assert response.status_code == 200

        _assert_logged_in(_rest_login(request_factory, STRONG))

    def test_without_mail_server_logs_in(
        self, enforced_without_mailhost, request_factory
    ):
        response = _rest_login(request_factory, WEAK)

        _assert_logged_in(response)
        assert "reset_token" not in response.text

    def test_without_email_address_logs_in(self, enforced, request_factory, mailhost):
        api.user.get(username=LOGIN).setMemberProperties({"email": ""})
        transaction.commit()

        _assert_logged_in(_rest_login(request_factory, WEAK))
        assert _sent_mails(mailhost) == []

    def test_mailing_passwords_disabled_logs_in(
        self, enforced, request_factory, mailhost
    ):
        api.portal.get().manage_permission("Mail forgotten password", roles=[])
        transaction.commit()

        _assert_logged_in(_rest_login(request_factory, WEAK))
        assert _sent_mails(mailhost) == []
