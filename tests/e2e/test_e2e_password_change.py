from email import message_from_bytes
from email import message_from_string
from interaktiv.passwordpolicy import PACKAGE_NAME
from plone import api
from plone.base.utils import get_installer
from Products.CMFPlone.tests.utils import MockMailHost

import pytest
import re
import transaction


LOGIN = "anton_autor"
WEAK = "Secret#123"
STRONG = "A much longer Secret#1234"


@pytest.fixture
def mailhost(functional_portal):
    mailhost = MockMailHost("MailHost")
    functional_portal.MailHost = mailhost
    api.portal.set_registry_record("plone.email_from_address", "site@example.com")
    return mailhost


@pytest.fixture
def stored_hash(functional_portal):
    def getter():
        transaction.begin()  # see the changes committed by the server
        return functional_portal.acl_users.source_users._user_passwords[LOGIN]

    return getter


def _create_user_without_addon(portal, email):
    installer = get_installer(portal)
    installer.uninstall_product(PACKAGE_NAME)
    api.user.create(email="anton@example.com", username=LOGIN, password=WEAK)

    if not email:
        api.user.get(username=LOGIN).setMemberProperties({"email": ""})

    transaction.commit()


def _install_addon_with_stricter_policy(portal):
    get_installer(portal).install_product(PACKAGE_NAME)
    api.portal.set_registry_record("interaktiv.passwordpolicy.min_password_length", 15)
    api.portal.set_registry_record(
        "interaktiv.passwordpolicy.require_change_on_login", True
    )
    transaction.commit()


def _login(session, password):
    session.get("/login")  # sets the test cookie the login form checks for
    return session.post(
        "/login",
        data={
            "__ac_name": LOGIN,
            "__ac_password": password,
            "buttons.login": "Log in",
        },
    )


def _new_session(request_factory):
    session = request_factory(api=False)
    session.headers["Accept"] = "text/html"
    return session


def _reset_token_from_email(mailhost):
    transaction.begin()
    [raw] = mailhost.messages
    message = (
        message_from_bytes(raw) if isinstance(raw, bytes) else message_from_string(raw)
    )
    # the body is quoted-printable encoded, decoding joins the wrapped lines
    body = "".join(
        part.get_payload(decode=True).decode()
        for part in message.walk()
        if not part.is_multipart()
    )

    return re.search(r"/passwordreset/([\w-]+)", body).group(1)


def _set_new_password(session, token):
    return session.post(
        f"/passwordreset/{token}",
        data={
            "userid": LOGIN,
            "password": STRONG,
            "password2": STRONG,
            "form.submitted": "1",
        },
    )


def _assert_new_password_works(request_factory, stored_hash, rehashed):
    new_hash = stored_hash()
    assert new_hash.startswith(b"{ARGON2}$argon2id$")
    assert new_hash != rehashed

    session = _new_session(request_factory)
    _login(session, STRONG)
    assert "__ac" in session.cookies


def test_with_email(functional_portal, request_factory, mailhost, stored_hash):
    _create_user_without_addon(functional_portal, email=True)
    assert stored_hash().startswith(b"{SSHA}")

    _install_addon_with_stricter_policy(functional_portal)
    session = _new_session(request_factory)
    response = _login(session, WEAK)

    rehashed = stored_hash()
    assert rehashed.startswith(b"{ARGON2}$argon2id$")
    assert "__ac" not in session.cookies
    assert "We have sent you an email" in response.text
    assert "/passwordreset/" not in response.url

    token = _reset_token_from_email(mailhost)
    response = _set_new_password(session, token)

    # plone.autologin_after_password_reset is enabled by default
    assert "__ac" in session.cookies
    _assert_new_password_works(request_factory, stored_hash, rehashed)


def test_without_email(functional_portal, request_factory, mailhost, stored_hash):
    _create_user_without_addon(functional_portal, email=False)
    assert stored_hash().startswith(b"{SSHA}")

    _install_addon_with_stricter_policy(functional_portal)
    session = _new_session(request_factory)
    response = _login(session, WEAK)

    rehashed = stored_hash()
    assert rehashed.startswith(b"{ARGON2}$argon2id$")
    assert "__ac" not in session.cookies
    assert "Please set a new password." in response.text
    assert mailhost.messages == []

    token = re.search(r"/passwordreset/([\w-]+)$", response.url).group(1)
    response = _set_new_password(session, token)

    assert "__ac" in session.cookies
    _assert_new_password_works(request_factory, stored_hash, rehashed)
