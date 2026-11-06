from interaktiv.passwordpolicy import _
from interaktiv.passwordpolicy import logger
from interaktiv.passwordpolicy.plugins.passwordpolicy import PasswordPolicyPlugin
from interaktiv.passwordpolicy.utils import get_setting
from plone import api
from plone.protect.utils import safeWrite
from plone.rest.interfaces import IAPIRequest
from zope.globalrequest import getRequest


PASSWORD_CHANGE_REQUIRED = "interaktiv.passwordpolicy.password_change_required"  # noqa: S105

PASSWORD_FIELD = "__ac_password"  # noqa: S105

# sent by clients that offer the password reset form with the returned token,
# e.g. volto-password-policy, for users who cannot receive the reset email
RESET_TOKEN_HEADER = "X-Password-Change"  # noqa: S105

PASSWORD_CHANGE_MESSAGE = _(
    "Your password does not meet the current password policy. Please set a new "
    "password."
)

PASSWORD_CHANGE_EMAIL_MESSAGE = _(
    "Your password does not meet the current password policy. We have sent you "
    "an email with a link to set a new password."
)


def password_change_required(password: str) -> bool:
    if not get_setting("require_change_on_login", False):
        return False

    request = getRequest()

    if request is None or request.form.get(PASSWORD_FIELD) != password:
        return False  # not an interactive login, e.g. HTTP Basic auth

    return bool(PasswordPolicyPlugin._validate_password(password))


def _create_reset_token(userid: str) -> str | None:
    reset_tool = api.portal.get_tool("portal_password_reset")
    reset = reset_tool.requestReset(userid)

    if reset is None:
        logger.warning(f"Could not create a password reset token for {userid!r}.")
        return None

    safeWrite(reset_tool)
    safeWrite(reset_tool._requests)

    return reset["randomstring"]


def _send_reset_email(login: str, request) -> bool:
    try:
        # immediately, otherwise a mail error only occurs on commit
        api.portal.get_tool("portal_registration").mailPassword(
            login, request, immediate=True
        )
    except Exception as error:
        logger.warning(f"Could not send password reset email to {login!r}: {error}")
        return False

    return True


def client_handles_reset_token(request) -> bool:
    return request.getHeader(RESET_TOKEN_HEADER) == "reset-token"


def refuse_login(userid: str, login: str) -> bool:
    request = getRequest()

    if PASSWORD_CHANGE_REQUIRED in request.other:
        # PAS may authenticate more than once per request
        return request.other[PASSWORD_CHANGE_REQUIRED] is not None

    # the email proves access to the mailbox, a token in the response only the
    # password; so the token is only for users who cannot receive the email
    refusal = None

    if _send_reset_email(login, request):
        refusal = {"token": None}
    elif not IAPIRequest.providedBy(request) or client_handles_reset_token(request):
        token = _create_reset_token(userid)

        if token is not None:
            refusal = {"token": token}

    request.other[PASSWORD_CHANGE_REQUIRED] = refusal

    if refusal is None:
        logger.warning(
            f"Allowing the login of {login!r} although the password does not "
            "meet the password policy, no password reset is possible."
        )
    else:
        logger.info(f"Refused login of {login!r}, password change required.")

    return refusal is not None


def reset_url(token: str) -> str:
    portal_state = api.content.get_view(
        "plone_portal_state", api.portal.get(), getRequest()
    )

    return f"{portal_state.navigation_root_url()}/passwordreset/{token}"
