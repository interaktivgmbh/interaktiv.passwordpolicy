from interaktiv.passwordpolicy.config import MIN_PASSWORD_LENGTH
from interaktiv.passwordpolicy.config import REGISTRY_PREFIX
from plone.registry.interfaces import IRegistry
from typing import Any
from zope.component import queryUtility


def get_setting(name: str, default: Any) -> Any:
    registry = queryUtility(IRegistry)
    if registry is None:
        return default

    return registry.get(f"{REGISTRY_PREFIX}.{name}", default)


def get_min_password_length() -> int:
    return get_setting("min_password_length", MIN_PASSWORD_LENGTH)
