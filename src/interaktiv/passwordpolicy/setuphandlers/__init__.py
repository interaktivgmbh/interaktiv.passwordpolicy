from Acquisition import aq_base
from AuthEncoding import AuthEncoding
from interaktiv.passwordpolicy import logger
from interaktiv.passwordpolicy import pas as pas_utils
from interaktiv.passwordpolicy.hashing import ARGON2_PREFIX
from interaktiv.passwordpolicy.plugins import passwordpolicy
from interaktiv.passwordpolicy.plugins import user as interaktiv_user
from plone import api
from plone.base.interfaces.installable import INonInstallable
from Products.PlonePAS.plugins.user import UserManager as PloneUserManager
from Products.PluggableAuthService.interfaces.plugins import IValidationPlugin
from Products.PluggableAuthService.PluggableAuthService import PluggableAuthService
from zope.interface import implementer


@implementer(INonInstallable)
class HiddenProfiles:
    def getNonInstallableProfiles(self):
        return [
            "interaktiv.passwordpolicy:uninstall",
        ]

    def getNonInstallableProducts(self):
        return [
            "interaktiv.passwordpolicy.upgrades",
        ]


PLUGIN_ID = "interaktiv_password_policy"
DEFAULT_PLUGIN_ID = "password_policy"
USER_MANAGER_ID = "source_users"


def _get_pas() -> PluggableAuthService:
    return api.portal.get().acl_users


def _is_active(pas: PluggableAuthService, plugin_id: str, interface) -> bool:
    return plugin_id in [p[0] for p in pas.plugins.listPlugins(interface)]


# PAS consults every active validator, Plone's default one has a fixed minimum
def install_password_policy() -> None:
    pas = _get_pas()

    if PLUGIN_ID in pas.objectIds():
        return

    pas_utils.add_plugin(
        pas=pas,
        plugin_id=PLUGIN_ID,
        manage_add=passwordpolicy.manage_addPasswordPolicyPlugin,
        plugin_title=passwordpolicy.PasswordPolicyPlugin.meta_type,
    )

    # only reactivated on uninstall if it was active before
    deactivated = _is_active(pas, DEFAULT_PLUGIN_ID, IValidationPlugin)
    pas[PLUGIN_ID]._deactivated_default_policy = deactivated

    if deactivated:
        pas_utils.deactivate_plugin_interface(pas, DEFAULT_PLUGIN_ID, IValidationPlugin)


def remove_password_policy() -> None:
    pas = _get_pas()

    if PLUGIN_ID not in pas.objectIds():
        return

    reactivate = getattr(pas[PLUGIN_ID], "_deactivated_default_policy", True)
    pas_utils.remove_plugin(pas, PLUGIN_ID)

    if reactivate:
        pas_utils.activate_plugin_interface(pas, DEFAULT_PLUGIN_ID, IValidationPlugin)


# replacing instead of changing __class__ keeps it transactional for all connections
def _replace_user_manager(from_class: type, to_class: type) -> bool:
    pas = _get_pas()
    old = pas._getOb(USER_MANAGER_ID, None)

    if old is None or type(aq_base(old)) is not from_class:
        logger.warning(
            f"Not replacing {USER_MANAGER_ID!r} by {to_class.__name__}: "
            f"expected {from_class.__module__}.{from_class.__name__}, "
            f"found {type(aq_base(old)).__module__}.{type(aq_base(old)).__name__}."
        )
        return False

    # deleting the plugin deactivates it for every plugin type
    registry = pas.plugins
    active = {}

    for info in registry.listPluginTypeInfo():
        ids = registry._getPlugins(info["interface"])

        if USER_MANAGER_ID in ids:
            active[info["interface"]] = tuple(ids)

    new = to_class(USER_MANAGER_ID)
    new.__dict__.clear()
    new.__dict__.update(aq_base(old).__dict__)

    pas._delObject(USER_MANAGER_ID, suppress_events=True)
    pas._setObject(USER_MANAGER_ID, new)

    for interface, ids in active.items():
        registry._plugins[interface] = ids

    logger.info(f"Replaced {USER_MANAGER_ID!r} by {to_class.__name__}.")

    return True


def install_user_manager() -> None:
    _replace_user_manager(PloneUserManager, interaktiv_user.UserManager)


def remove_user_manager() -> None:
    if _replace_user_manager(interaktiv_user.UserManager, PloneUserManager):
        _warn_about_argon2_hashes()


def _warn_about_argon2_hashes() -> None:
    passwords = _get_pas()[USER_MANAGER_ID]._user_passwords
    count = sum(
        1
        for pw in passwords.values()
        if AuthEncoding.to_bytes(pw).startswith(ARGON2_PREFIX)
    )

    if count:
        logger.warning(
            f"{count} user(s) have Argon2id password hashes. They can log in as "
            "long as interaktiv.argon2 remains installed. If you remove "
            "interaktiv.passwordpolicy from your dependencies, add "
            "interaktiv.argon2 to them, otherwise these users need to reset "
            "their password."
        )


def post_install(context):
    install_password_policy()
    install_user_manager()


def uninstall(context):
    remove_password_policy()
    remove_user_manager()
