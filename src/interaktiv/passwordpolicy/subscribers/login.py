from interaktiv.passwordpolicy.password_change import PASSWORD_CHANGE_EMAIL_MESSAGE
from interaktiv.passwordpolicy.password_change import PASSWORD_CHANGE_MESSAGE
from interaktiv.passwordpolicy.password_change import PASSWORD_CHANGE_REQUIRED
from interaktiv.passwordpolicy.password_change import reset_url
from plone.rest.interfaces import IAPIRequest
from Products.statusmessages.adapter import STATUSMESSAGEKEY
from Products.statusmessages.interfaces import IStatusMessage
from zope.annotation.interfaces import IAnnotations

import re


RESET_COOKIE = "interaktiv_passwordpolicy_reset"


def classic_login_refused(event) -> None:
    request = event.request
    refusal = request.other.get(PASSWORD_CHANGE_REQUIRED)

    if refusal is None or IAPIRequest.providedBy(request):
        return

    token = refusal["token"]
    message = (
        PASSWORD_CHANGE_EMAIL_MESSAGE if token is None else PASSWORD_CHANGE_MESSAGE
    )

    # replace "Login failed", the login form already expired the message cookie
    IAnnotations(request)[STATUSMESSAGEKEY] = None
    request.response.cookies.pop(STATUSMESSAGEKEY, None)
    IStatusMessage(request).add(message, type="warning")

    if request.getHeader("X-Requested-With") != "XMLHttpRequest":
        # back to the login form for the message, or on to the reset form
        url = request["ACTUAL_URL"] if token is None else reset_url(token)
        request.response.redirect(url)
        return

    # Plone's login modal reloads the page after a response without errors;
    # setBody ignores an empty body
    request.response.setBody("<html><body></body></html>")

    if token is None:
        return

    request.response.setCookie(
        RESET_COOKIE,
        token,
        path="/",
        max_age=300,
        http_only=True,
        same_site="Lax",
        secure=request.get("SERVER_URL", "").startswith("https"),
    )


def redirect_to_password_reset(event) -> None:
    request = event.request
    token = request.cookies.get(RESET_COOKIE)

    if not token or IAPIRequest.providedBy(request):
        return

    if "text/html" not in request.getHeader("Accept", ""):
        return  # e.g. a favicon, wait for the page itself

    request.response.expireCookie(RESET_COOKIE, path="/")

    if re.fullmatch(r"[\w-]+", token):
        request.response.redirect(reset_url(token))
