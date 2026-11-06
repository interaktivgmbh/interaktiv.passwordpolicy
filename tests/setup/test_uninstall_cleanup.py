from interaktiv.passwordpolicy import PACKAGE_NAME
from plone.base.utils import get_installer
from ZODB.serialize import referencesf
from ZODB.utils import z64

import transaction


# plain files, e.g. GenericSetup's import logs, mention the package as text
# but cannot load any code
IGNORED_CLASSES = (b"cOFS.Image\nFile\n",)


def _referencing_records(db, needle: bytes) -> list[bytes]:
    storage = db.storage
    seen, todo, found = set(), [z64], []
    while todo:
        oid = todo.pop()
        if oid in seen:
            continue
        seen.add(oid)
        data, _serial = storage.load(oid)
        if needle in data and not data[2:].startswith(IGNORED_CLASSES):
            found.append(data)
        todo.extend(referencesf(data))
    return found


# module paths, e.g. "interaktiv.passwordpolicy.plugins.user" or the
# registry interface "interaktiv.passwordpolicy.controlpanels..."
NEEDLE = f"{PACKAGE_NAME}.".encode()


def test_references_while_installed(functional_portal):
    transaction.commit()

    assert _referencing_records(functional_portal._p_jar.db(), NEEDLE)


def test_no_references_after_uninstall(functional_portal):
    get_installer(functional_portal).uninstall_product(PACKAGE_NAME)
    transaction.commit()

    assert _referencing_records(functional_portal._p_jar.db(), NEEDLE) == []


def test_no_references_to_argon2_package(functional_portal):
    transaction.commit()

    db = functional_portal._p_jar.db()
    assert _referencing_records(db, b"interaktiv.argon2") == []
