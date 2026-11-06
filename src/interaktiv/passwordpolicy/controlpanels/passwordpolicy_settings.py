from interaktiv.passwordpolicy import _
from interaktiv.passwordpolicy.config import MIN_PASSWORD_LENGTH
from interaktiv.passwordpolicy.config import REGISTRY_PREFIX
from interaktiv.passwordpolicy.hashing import DEFAULT_PROFILE
from interaktiv.passwordpolicy.interfaces import IBrowserLayer
from plone import schema
from plone.app.registry.browser.controlpanel import ControlPanelFormWrapper
from plone.app.registry.browser.controlpanel import RegistryEditForm
from plone.restapi.controlpanels import RegistryConfigletPanel
from plone.z3cform import layout
from zope.component import adapter
from zope.interface import Interface


class IPasswordPolicySettings(Interface):
    min_password_length = schema.Int(
        title=_("Minimum password length"),
        description=_("The minimum number of characters a password must contain."),
        default=MIN_PASSWORD_LENGTH,
        min=1,
        required=True,
    )

    require_lowercase = schema.Bool(
        title=_("Require a lower case letter"),
        default=True,
        required=False,
    )

    require_uppercase = schema.Bool(
        title=_("Require an upper case letter"),
        default=True,
        required=False,
    )

    require_number = schema.Bool(
        title=_("Require a number"),
        default=True,
        required=False,
    )

    require_special = schema.Bool(
        title=_("Require a special character"),
        description=_(
            "Every character that is neither a letter nor a number counts as "
            "special character, e.g. spaces, punctuation or symbols like €."
        ),
        default=True,
        required=False,
    )

    require_change_on_login = schema.Bool(
        title=_("Require a password change at login"),
        description=_(
            "If a password does not meet the policy above, the login is refused "
            "and the user has to set a new password first. Only applies to "
            "logins through the login form, not to HTTP Basic authentication "
            "(e.g. technical users)."
        ),
        default=False,
        required=False,
    )

    argon2_profile = schema.Choice(
        title=_("Password hashing cost (Argon2id)"),
        description=_(
            "Memory and time used to hash a password. All profiles are equally "
            "strong; less memory is compensated by more iterations. Choose a "
            "lower memory profile if the server cannot afford the memory per "
            "login. Only applies to newly set passwords."
        ),
        vocabulary="interaktiv.passwordpolicy.argon2_profiles",
        default=DEFAULT_PROFILE,
        required=True,
    )


class PasswordPolicyForm(RegistryEditForm):
    schema = IPasswordPolicySettings
    schema_prefix = REGISTRY_PREFIX
    label = _("Password Policy Settings")


@adapter(Interface, IBrowserLayer)
class PasswordPolicyConfigletPanel(RegistryConfigletPanel):
    schema = IPasswordPolicySettings
    schema_prefix = REGISTRY_PREFIX
    configlet_id = "passwordpolicy-controlpanel"
    configlet_category_id = "Products"
    title = "Password Policy"
    group = "Products"


PasswordPolicyView = layout.wrap_form(PasswordPolicyForm, ControlPanelFormWrapper)
