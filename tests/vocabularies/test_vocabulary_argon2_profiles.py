from interaktiv.passwordpolicy.hashing import PROFILES

import pytest


VOCABULARY = "interaktiv.passwordpolicy.argon2_profiles"


@pytest.fixture
def vocabulary(portal, get_vocabulary):
    return get_vocabulary(VOCABULARY, portal)


def test_vocabulary_contains_all_profiles(vocabulary):
    assert [term.value for term in vocabulary] == list(PROFILES)


def test_vocabulary_default_is_recommended(vocabulary):
    term = vocabulary.getTerm("rfc9106-low-memory")
    assert "recommended" in term.title
