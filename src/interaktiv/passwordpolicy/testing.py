from plone.app.contenttypes.testing import PLONE_APP_CONTENTTYPES_FIXTURE
from plone.app.testing import applyProfile
from plone.app.testing import FunctionalTesting
from plone.app.testing import IntegrationTesting
from plone.app.testing import PloneSandboxLayer
from plone.testing import zope
from plone.testing.zope import WSGI_SERVER_FIXTURE

import interaktiv.passwordpolicy


class Layer(PloneSandboxLayer):
    defaultBases = (PLONE_APP_CONTENTTYPES_FIXTURE,)

    def setUpZope(self, app, configurationContext):
        import plone.restapi

        self.loadZCML(package=plone.restapi)
        self.loadZCML(package=interaktiv.passwordpolicy)
        # runs `initialize`, registering the PAS plugins
        zope.installProduct(app, "interaktiv.passwordpolicy")

    def setUpPloneSite(self, portal):
        # like a Volto site; the add-on itself does not require it
        applyProfile(portal, "plone.restapi:default")
        applyProfile(portal, "interaktiv.passwordpolicy:default")


FIXTURE = Layer()

INTEGRATION_TESTING = IntegrationTesting(
    bases=(FIXTURE,),
    name="Interaktiv.PasswordpolicyLayer:IntegrationTesting",
)


FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(FIXTURE, WSGI_SERVER_FIXTURE),
    name="Interaktiv.PasswordpolicyLayer:FunctionalTesting",
)
