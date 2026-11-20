# Changelog

<!--
   You should *NOT* be adding new change log entries to this file.
   You should create a file in the news directory instead.
   For helpful instructions, please see:
   https://github.com/plone/plone.releaser/blob/master/ADD-A-NEWS-ITEM.rst
-->

<!-- towncrier release notes start -->

## 1.0.1 (2026-11-20)


### Bugfix

- Verify a dummy hash for unknown login names to prevent user enumeration via timing attacks. @arybakov05 [#2](https://github.com/interaktivgmbh/interaktiv.passwordpolicy/issues/2)


### Tests

- Test that generated password detection matches Plone's generatePassword(). @arybakov05 [#1](https://github.com/interaktivgmbh/interaktiv.passwordpolicy/issues/1)

## 1.0.0 (2026-11-06)


### Feature

- Initial release: configurable password policy (minimum length, lower and upper case letters, numbers, special characters) with a control panel for Classic UI and Volto.
- Argon2id password hashing through `interaktiv.argon2`, with six cost profiles and transparent rehashing on login.
- Optional password change at login for passwords that do not meet the policy.
