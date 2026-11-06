from zope.i18nmessageid import MessageFactory

import logging


__version__ = "1.0.0"

PACKAGE_NAME = "interaktiv.passwordpolicy"

_ = MessageFactory(PACKAGE_NAME)

logger = logging.getLogger(PACKAGE_NAME)


def initialize(context):
    from AccessControl.Permissions import add_user_folders
    from interaktiv.passwordpolicy.plugins import passwordpolicy
    from interaktiv.passwordpolicy.plugins import user
    from Products.PluggableAuthService import registerMultiPlugin

    registerMultiPlugin(passwordpolicy.PasswordPolicyPlugin.meta_type)
    registerMultiPlugin(user.UserManager.meta_type)

    context.registerClass(
        passwordpolicy.PasswordPolicyPlugin,
        permission=add_user_folders,
        constructors=(
            passwordpolicy.manage_addPasswordPolicyForm,
            passwordpolicy.manage_addPasswordPolicyPlugin,
        ),
        visibility=None,
    )
    context.registerClass(
        user.UserManager,
        permission=add_user_folders,
        constructors=(
            user.manage_addUserManagerForm,
            user.manage_addUserManager,
        ),
        visibility=None,
    )
