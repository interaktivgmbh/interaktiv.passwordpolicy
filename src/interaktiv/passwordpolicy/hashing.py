from AuthEncoding import AuthEncoding
from functools import cache
from interaktiv.argon2 import ARGON2
from interaktiv.argon2 import ARGON2_PREFIX
from interaktiv.argon2 import DEFAULT_PROFILE
from interaktiv.argon2 import PROFILES
from interaktiv.passwordpolicy.utils import get_setting

import interaktiv.argon2
import secrets


__all__ = [
    "ARGON2",
    "ARGON2_PREFIX",
    "DEFAULT_PROFILE",
    "PROFILES",
    "get_profile",
    "hash_password",
    "needs_rehash",
    "verify_dummy",
]


def get_profile() -> str:
    profile = get_setting("argon2_profile", DEFAULT_PROFILE)
    if profile not in PROFILES:
        return DEFAULT_PROFILE

    return profile


def hash_password(password: str | bytes) -> bytes:
    return interaktiv.argon2.hash_password(password, get_profile())


def needs_rehash(reference: str | bytes) -> bool:
    return interaktiv.argon2.needs_rehash(reference, get_profile())


@cache
def _dummy_hash(profile: str) -> bytes:
    return interaktiv.argon2.hash_password(secrets.token_urlsafe(), profile)


def verify_dummy(password: str | bytes) -> None:
    AuthEncoding.pw_validate(_dummy_hash(get_profile()), password)
