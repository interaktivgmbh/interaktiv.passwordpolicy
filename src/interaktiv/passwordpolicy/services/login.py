from interaktiv.passwordpolicy.password_change import PASSWORD_CHANGE_EMAIL_MESSAGE
from interaktiv.passwordpolicy.password_change import PASSWORD_CHANGE_MESSAGE
from interaktiv.passwordpolicy.password_change import PASSWORD_CHANGE_REQUIRED
from plone.restapi.services.auth.login import Login as BaseLogin
from zope.i18n import translate


class Login(BaseLogin):
    def reply(self):
        result = super().reply()
        refusal = self.request.other.get(PASSWORD_CHANGE_REQUIRED)

        if refusal is None:
            return result

        token = refusal["token"]
        message = (
            PASSWORD_CHANGE_EMAIL_MESSAGE if token is None else PASSWORD_CHANGE_MESSAGE
        )
        error = {
            "type": "Password change required",
            "message": translate(message, context=self.request),
        }

        if token is not None:
            error["reset_token"] = token

        self.request.response.setStatus(401)

        return {"error": error}
