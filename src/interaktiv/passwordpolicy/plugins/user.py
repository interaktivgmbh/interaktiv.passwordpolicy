from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass
from App.special_dtml import DTMLFile
from AuthEncoding import AuthEncoding
from interaktiv.passwordpolicy import logger
from interaktiv.passwordpolicy.hashing import hash_password
from interaktiv.passwordpolicy.hashing import needs_rehash
from interaktiv.passwordpolicy.password_change import password_change_required
from interaktiv.passwordpolicy.password_change import refuse_login
from plone.protect.utils import safeWrite
from Products.PlonePAS.plugins.user import UserManager as PloneUserManager
from Products.PluggableAuthService.events import CredentialsUpdated
from zope.event import notify


manage_addUserManagerForm = DTMLFile("../zmi/UserManagerForm", globals())


def manage_addUserManager(dispatcher, id, title=None, REQUEST=None):  # noqa: A002
    """Add an Interaktiv UserManager to a Pluggable Auth Service."""
    pum = UserManager(id, title)
    dispatcher._setObject(pum.getId(), pum)

    if REQUEST is not None:
        REQUEST["RESPONSE"].redirect(
            f"{dispatcher.absolute_url()}/manage_workspace"
            "?manage_tabs_message=UserManager+added."
        )


class UserManager(PloneUserManager):
    meta_type = "Interaktiv User Manager"
    security = ClassSecurityInfo()

    # used by updateUserPassword (ZMI) and addUser
    @security.private
    def _pw_encrypt(self, password):
        if AuthEncoding.is_encrypted(password):
            return password

        return hash_password(password)

    def addUser(self, user_id, login_name, password):
        # PloneUserManager.addUser keeps hashed passwords as is
        super().addUser(user_id, login_name, self._pw_encrypt(password))

    @security.private
    def doChangeUser(self, principal_id, password):
        if self._user_passwords.get(principal_id) is None:
            raise RuntimeError(f"User does not exist: {principal_id}")

        self._user_passwords[principal_id] = hash_password(password)
        notify(CredentialsUpdated(self.getUserById(principal_id), password))

    @security.private
    def authenticateCredentials(self, credentials):
        result = super().authenticateCredentials(credentials)

        if result is None:
            return None

        userid, login = result
        password = credentials["password"]
        self._rehash_password(userid, password)

        if password_change_required(password) and refuse_login(userid, login):
            return None

        return result

    def _rehash_password(self, userid, password):
        reference = self._user_passwords.get(userid)

        if reference is None or not needs_rehash(reference):
            return

        jar = self._p_jar

        if jar is not None and jar.isReadOnly():
            return

        self._user_passwords[userid] = hash_password(password)
        safeWrite(self._user_passwords)
        logger.info(f"Rehashed password of user {userid!r}.")


InitializeClass(UserManager)
