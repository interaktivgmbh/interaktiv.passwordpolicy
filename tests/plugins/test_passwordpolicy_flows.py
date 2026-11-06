from plone import api

import pytest
import transaction


@pytest.fixture
def member(functional_portal):
    password = "Secret#123456"
    api.user.create(
        email="member@example.com", username="member_abc", password=password
    )
    transaction.commit()
    return password


@pytest.fixture
def self_registration(functional_portal):
    from Products.CMFPlone.tests.utils import MockMailHost

    functional_portal.MailHost = MockMailHost("MailHost")
    api.portal.set_registry_record("plone.email_from_address", "site@example.com")
    api.portal.set_registry_record("plone.enable_self_reg", True)
    api.portal.set_registry_record("plone.enable_user_pwd_choice", False)
    transaction.commit()


def test_change_password_rejects_weak(member, request_factory):
    session = request_factory(basic_auth=("member_abc", member))

    response = session.post(
        "/@users/member_abc/reset-password",
        json={"old_password": member, "new_password": "weak"},
    )

    assert response.status_code == 400


def test_sendPasswordReset_flag_does_not_bypass(member, request_factory):
    session = request_factory(basic_auth=("member_abc", member))

    response = session.post(
        "/@users/member_abc/reset-password",
        json={
            "old_password": member,
            "new_password": "weak",
            "sendPasswordReset": True,
        },
    )

    assert response.status_code == 400


def test_self_registration_with_reset_link(self_registration, request_factory):
    response = request_factory().post(
        "/@users", json={"email": "self@example.com", "username": "selfreg"}
    )

    assert response.status_code == 201
    transaction.begin()
    assert api.user.get(username="selfreg") is not None


def test_add_member_with_generated_password(functional_portal):
    registration = functional_portal.portal_registration

    registration.addMember("generated", registration.generatePassword())

    assert api.user.get(username="generated") is not None


def test_add_member_with_weak_password(functional_portal):
    registration = functional_portal.portal_registration

    with pytest.raises(ValueError):
        registration.addMember("weak", "weak")
