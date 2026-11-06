from interaktiv.passwordpolicy import _
from interaktiv.passwordpolicy.hashing import PROFILES
from zope.interface import provider
from zope.schema.interfaces import IVocabularyFactory
from zope.schema.vocabulary import SimpleTerm
from zope.schema.vocabulary import SimpleVocabulary


TITLES = {
    "rfc9106-low-memory": _("64 MiB memory, 3 iterations, 4 lanes (recommended)"),
    "owasp-46m": _("46 MiB memory, 1 iteration, 1 lane"),
    "owasp-19m": _("19 MiB memory, 2 iterations, 1 lane"),
    "owasp-12m": _("12 MiB memory, 3 iterations, 1 lane"),
    "owasp-9m": _("9 MiB memory, 4 iterations, 1 lane"),
    "owasp-7m": _("7 MiB memory, 5 iterations, 1 lane"),
}


@provider(IVocabularyFactory)
def argon2_profiles_vocabulary(context):
    return SimpleVocabulary([
        SimpleTerm(value=name, token=name, title=TITLES[name]) for name in PROFILES
    ])
