from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass
from collections.abc import Callable
from contextlib import suppress
from interaktiv.passwordpolicy import _
from interaktiv.passwordpolicy.utils import get_min_password_length
from interaktiv.passwordpolicy.utils import get_setting
from Products.CMFPlone.RegistrationTool import password_chars
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.interfaces.plugins import IValidationPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from typing import NamedTuple
from zope.globalrequest import getRequest
from zope.i18n import translate
from zope.i18nmessageid import Message
from zope.interface import implementer

import json


manage_addPasswordPolicyForm = PageTemplateFile("../zmi/PasswordPolicyForm", globals())

# see Products.CMFPlone.RegistrationTool.generatePassword
GENERATED_PASSWORD_LENGTH = 56
GENERATED_PASSWORD_CHARS = frozenset(password_chars)


class Requirement(NamedTuple):
    setting: str
    check: Callable[[str], bool]
    message: Message


PASSWORD_REQUIREMENTS = (
    Requirement(
        "require_lowercase",
        lambda pw: any(c.islower() for c in pw),
        _("Your password must contain at least one lower case letter."),
    ),
    Requirement(
        "require_uppercase",
        lambda pw: any(c.isupper() for c in pw),
        _("Your password must contain at least one upper case letter."),
    ),
    Requirement(
        "require_number",
        lambda pw: any(c.isdecimal() for c in pw),
        _("Your password must contain at least one number."),
    ),
    Requirement(
        "require_special",
        lambda pw: any(not c.isalnum() for c in pw),
        _("Your password must contain at least one special character."),
    ),
)


def password_too_short(min_length: int):
    return _(
        "Your password must contain at least ${min_chars} characters.",
        mapping={"min_chars": str(min_length)},
    )


def _request_values(request) -> set[str]:
    values = set()

    def collect(value):
        if isinstance(value, str):
            values.add(value)
        elif isinstance(value, dict):
            for item in value.values():
                collect(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                collect(item)

    collect(dict(request.form))
    with suppress(TypeError, ValueError):
        collect(json.loads(request.get("BODY") or "null"))
    return values


# a password the client sent is never considered generated
def is_generated_password(password: str | None, request) -> bool:
    if not password or len(password) != GENERATED_PASSWORD_LENGTH:
        return False

    if not set(password) <= GENERATED_PASSWORD_CHARS:
        return False

    return request is None or password not in _request_values(request)


def manage_addPasswordPolicyPlugin(self, id, title="", RESPONSE=None, **kw):  # noqa: A002
    """Create an instance of the password validation plugin."""
    o = PasswordPolicyPlugin(id, title)
    self._setObject(o.getId(), o)

    if RESPONSE is not None:
        return RESPONSE.redirect(
            f"{self.absolute_url()}/manage_workspace?"
            "manage_tabs_message=PasswordPolicyPlugin+plugin+added"
        )


@implementer(IValidationPlugin)
class PasswordPolicyPlugin(BasePlugin):
    meta_type = "Interaktiv Password Policy"

    security = ClassSecurityInfo()

    def __init__(self, id, title=""):  # noqa: A002
        self.id = id
        self.title = title

    @security.private
    def validateUserInfo(self, user, set_id, set_info):
        if not set_info:
            return []

        password = set_info.get("password", None)
        if is_generated_password(password, getRequest()):
            return []

        return self._validate_password(password)

    @staticmethod
    def _validate_password(password: str) -> list[dict[str, str]]:
        errors = []

        if password:
            min_length = get_min_password_length()

            if len(password) < min_length:
                return [
                    {
                        "id": "password",
                        "error": translate(
                            password_too_short(min_length), context=getRequest()
                        ),
                    }
                ]

            for requirement in PASSWORD_REQUIREMENTS:
                if not get_setting(requirement.setting, True):
                    continue

                if not requirement.check(password):
                    errors.append({
                        "id": "password",
                        "error": translate(requirement.message, context=getRequest()),
                    })

        return errors


InitializeClass(PasswordPolicyPlugin)
