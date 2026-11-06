# interaktiv.passwordpolicy

A configurable password policy and modern password hashing for Plone.

`interaktiv.passwordpolicy` replaces Plone's fixed "at least 8 characters" rule with a policy you configure in a control panel.
It also stores passwords with Argon2id instead of salted SHA-1, and upgrades existing passwords transparently when users log in.

## Features

- **Configurable password policy**: set the minimum length and choose whether a password must contain a lower case letter, an upper case letter, a number, or a special character.
- **Unicode-aware checks**: `Ä` counts as an upper case letter, and `€` or a space counts as a special character.
- **Argon2id password hashing**: new and changed passwords are hashed with Argon2id, the winner of the Password Hashing Competition and the first recommendation of OWASP.
  The hashing scheme lives in the separate library `interaktiv.argon2`, so Argon2id hashes stay valid after you remove the add-on.
- **Hashing profiles for every server size**: choose between six equally strong Argon2id profiles that use between 64 MiB and 7 MiB of memory per login.
- **Password change at login (optional)**: users whose password does not meet a stricter policy get a password reset email instead of a session.
- **Transparent rehashing on login**: existing passwords are upgraded to the current Argon2id profile when their users log in, without any action from the users.
- **Builds on Plone's defaults**: the add-on adds its own PAS plugins and deactivates Plone's default password policy instead of deleting it, so uninstalling restores the original setup.
- **Classic UI and Volto**: the control panel works in Classic UI and through the REST API `@controlpanels` endpoint used by Volto.
  For the password change at login in Volto, use [volto-password-policy](https://github.com/interaktivgmbh/volto-password-policy).
- **Translations**: English and German.

## Installation

Add `interaktiv.passwordpolicy` to the dependencies of your project, for example in `pyproject.toml`:

```toml
dependencies = [
    "interaktiv.passwordpolicy",
]
```

This also installs [interaktiv.argon2](https://github.com/interaktivgmbh/interaktiv.argon2), the library that provides the Argon2id hashing scheme.
Read [Password hashing](#password-hashing) for why it is a separate package.

### From PyPI

Your package manager installs the add-on from [PyPI](https://pypi.org/project/interaktiv.passwordpolicy/), no further configuration is needed.
Without a `pyproject.toml`, install it with `pip`:

```shell
pip install interaktiv.passwordpolicy
```

### From GitHub with mxdev

If your project uses [mxdev](https://pypi.org/project/mxdev/), add the repository as a source in your `mx.ini`:

```ini
[interaktiv.passwordpolicy]
url = git@github.com:interaktivgmbh/interaktiv.passwordpolicy.git
branch = main
```

### Volto

For the password change at login, also add [volto-password-policy](https://github.com/interaktivgmbh/volto-password-policy) to your Volto project.
Without it, Volto shows its generic "Login failed" message to users who have to change their password.

### Install the add-on in your site

1. Open **Site Setup** → **Add-ons**.
2. Install **Interaktiv Passwordpolicy: Install**.

To install it together with your policy package, add the profile as a dependency in your `metadata.xml`:

```xml
<dependency>profile-interaktiv.passwordpolicy:default</dependency>
```

## Configuration

Open **Site Setup** → **Add-on Configuration** → **Password Policy**.
In Volto, the control panel is available at `/controlpanel/passwordpolicy-controlpanel`.

| Setting | Default | Description |
|---|---|---|
| Minimum password length | `8` | The minimum number of characters a password must contain. |
| Require a lower case letter | on | The password must contain at least one lower case letter. |
| Require an upper case letter | on | The password must contain at least one upper case letter. |
| Require a number | on | The password must contain at least one digit. |
| Require a special character | on | The password must contain at least one character that is neither a letter nor a digit. |
| Require a password change at login | off | Refuse logins with passwords that do not meet the policy. See [Password change at login](#password-change-at-login). |
| Password hashing cost (Argon2id) | 64 MiB | The Argon2id profile for newly hashed passwords. See [Argon2id hashing profiles](#argon2id-hashing-profiles). |

The settings are stored in the Plone registry with the prefix `interaktiv.passwordpolicy`.

The policy applies whenever a password is set, for example on registration, password change, or password reset.
Changing the policy does not affect existing passwords until their users set a new one.

### Password change at login

By default, a stricter policy only applies to passwords set afterwards.
To enforce it for existing passwords too, turn on **Require a password change at login**.

When a user logs in with a correct password that does not meet the policy, the add-on refuses the login, and the user has to set a new password first.
The new password must meet the policy.
No session exists until the password is changed, so the policy cannot be skipped by navigating away.

The add-on sends Plone's password reset email whenever possible.
The email proves access to the mailbox, so someone who only knows the old password cannot take over the account.
Only users who cannot receive the email, for example without an email address or without a mail server, get a one-time reset token right away.

- **Classic UI** shows a message that explains the refused login.
  Without email, it redirects to Plone's password reset form with the one-time token, and after setting the new password, the user is logged in.
- **The `@login` REST API endpoint** answers with status `401` and the error type `Password change required`.
  Without email, it includes the one-time token as `reset_token` if the client asks for it with the header `X-Password-Change: reset-token`.
  A client can offer the password reset form with it, for example through `POST @users/<username>/reset-password` with `reset_token` and `new_password`.
  For Volto, [volto-password-policy](https://github.com/interaktivgmbh/volto-password-policy) does that.
  Without the header and without email, the add-on allows the login and logs a warning, so that no user is locked out.
- **HTTP Basic authentication** is not affected, because technical users and integrations authenticate with it on every request.

The setting applies to every user with a non-compliant password, including administrators.

### Recommended settings according to NIST

The defaults keep the composition rules that many organizations still expect.
If you want to follow [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html) instead, use the following settings:

- Set the minimum password length to `15`, or to `8` if passwords are only used together with a second factor.
- Turn off all four "Require" checkboxes.

Read [Why every character counts as a special character](#why-every-character-counts-as-a-special-character) for the reasoning behind these recommendations.

## Argon2id hashing profiles

A password hash must be slow to compute, so that an attacker who steals the user database cannot try billions of guesses per second.
Argon2id is slow in two ways: it needs time, and it needs memory.

The memory is the important part.
A graphics card has thousands of cores, but only a small amount of memory per core.
Because every single guess needs the full amount of memory, an attacker cannot run thousands of guesses in parallel.
Older algorithms such as SHA-1 or SHA-256 need almost no memory, so graphics cards compute them extremely fast.

### Memory usage on your server

Your server needs the same memory as the attacker, but only once per login.
The memory is allocated for each hash computation and released right afterwards.
A hash computation happens when a user sets a password and when a user logs in.

Simultaneous logins add up.
With the default profile, 20 users who log in at the same moment need about 1.25 GiB of memory for a short time.
If your server or container cannot afford that, choose a profile with less memory.

### Available profiles

| Profile | Memory | Iterations | Lanes | Source |
|---|---|---|---|---|
| `rfc9106-low-memory` (default) | 64 MiB | 3 | 4 | [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html#section-4), second recommended option |
| `owasp-46m` | 46 MiB | 1 | 1 | [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id) |
| `owasp-19m` | 19 MiB | 2 | 1 | OWASP |
| `owasp-12m` | 12 MiB | 3 | 1 | OWASP |
| `owasp-9m` | 9 MiB | 4 | 1 | OWASP |
| `owasp-7m` | 7 MiB | 5 | 1 | OWASP |

The profiles are defined in `interaktiv.argon2`.
According to OWASP, the five OWASP profiles "provide an equal level of defense, and the only difference is a trade off between CPU and RAM usage".
A profile with less memory compensates with more iterations, so it takes more CPU time per login instead.
Lanes split the memory into independent parts that can be computed in parallel.

Prefer the default profile if your server can afford it, and choose the profile with the most memory your server can afford otherwise.

### Changing the profile

You can change the profile at any time without locking out any user.
Each hash stores its own salt and cost parameters, for example:

```text
{ARGON2}$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
```

The add-on always verifies a password with the parameters stored in its hash.
After a successful login, it rehashes the password if the stored parameters differ from the current profile.
Users who never log in keep their old hash until they set a new password.

The same rehashing upgrades passwords from before the installation of the add-on.
Plone stores these as salted SHA-1 (`{SSHA}`), and older sites may still contain other formats.

## Why every character counts as a special character

The add-on accepts every character in a password, including spaces, umlauts, emojis, and characters of every other script.
When the special character rule is active, every character that is neither a letter nor a digit counts as a special character.

Many password policies define special characters as a fixed list of ASCII punctuation, such as ``!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~``.
Such a list has two problems:

- A strong password such as `Grüne Wiese 2024` does not satisfy the rule, although its space makes it harder to guess.
- If the list restricts the allowed characters, the policy rejects strong passwords for no security benefit.

[NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html) (Revision 4, section 3.1.1.2 "Password verifiers") states that verifiers "SHOULD accept all printing ASCII characters and the space character in passwords" and "SHOULD accept Unicode characters in passwords".
The add-on follows these recommendations, and therefore does not offer a setting for the list of special characters.

The same section goes one step further: verifiers "SHALL NOT impose other composition rules (e.g., requiring mixtures of different character types) for passwords".
Composition rules push users toward predictable patterns such as `Password1!`, while the length of a password matters much more.
The add-on keeps the composition rules as optional checkboxes, so you can follow NIST by turning them off and raising the minimum length.
Read [Recommended settings according to NIST](#recommended-settings-according-to-nist) for the exact settings.

## How it works

The add-on installs two plugins into the Pluggable Authentication Service (PAS) of your site, `acl_users`.

- **`interaktiv_password_policy`** is the password policy, a validation plugin.
  PAS consults every active validation plugin, so the add-on deactivates Plone's default `password_policy` plugin.
  Otherwise, Plone's fixed minimum of 8 characters would still apply and produce contradicting error messages.
  The default plugin stays in place, and the add-on reactivates it on uninstall if it was active before.
- **`source_users`** is a user manager that hashes passwords with Argon2id and rehashes them on login.
  The add-on replaces Plone's `source_users` with an identical plugin of its own class: the very same users, passwords, and login names, and the same position in every plugin list.
  If `source_users` is not Plone's default user manager, for example a project specific one, the add-on leaves it alone and logs a warning.
  On uninstall, the add-on replaces it back the same way.

### Password hashing

The `ARGON2` hashing scheme for AuthEncoding, the library Zope and Plone use to hash and verify passwords, lives in the separate package `interaktiv.argon2`.
It is a plain Python library without installation profile, and it never writes anything to the database.
Plone imports it at startup through its `z3c.autoinclude` entry point, and importing it registers the scheme in memory.
AuthEncoding then picks the scheme by the `{ARGON2}` prefix of a stored hash, so every user manager can verify Argon2id hashes, including Plone's default one.

The add-on itself only decides which cost profile to use for new hashes, according to the control panel.
Because the scheme does not depend on the add-on, Argon2id hashes stay valid when you remove the add-on, as long as `interaktiv.argon2` remains installed.
Read [Uninstalling](#uninstalling) for the steps.

### Generated passwords

When users get a password reset link instead of choosing a password, Plone sets a random password that they never see, for example on self registration without password choice.
The password policy does not validate these generated passwords.
A password that a client sends is always validated.

### Uninstalling

Uninstalling the add-on restores Plone's default PAS plugins and removes the control panel and its settings.
Afterwards, the database contains no references to the code of the add-on.

Argon2id hashes stay valid after the uninstall, because the hashing scheme lives in `interaktiv.argon2`, see [Password hashing](#password-hashing).
To remove the add-on completely:

1. Uninstall **Interaktiv Passwordpolicy** in **Site Setup** → **Add-ons**.
2. Replace `interaktiv.passwordpolicy` with `interaktiv.argon2` in the dependencies of your project.

```toml
dependencies = [
    "interaktiv.argon2",
]
```

If you install the add-on from GitHub through mxdev, also remove the `[interaktiv.passwordpolicy]` source from your `mx.ini`.

Keep `interaktiv.argon2` installed as long as passwords are stored as Argon2id hashes.
Otherwise, your package manager removes it together with `interaktiv.passwordpolicy`, and these users can no longer log in until they reset their password.
On uninstall, the add-on logs how many users have Argon2id hashes.

## Contribute

- [Issue tracker](https://github.com/interaktivgmbh/interaktiv.passwordpolicy/issues)
- [Source code](https://github.com/interaktivgmbh/interaktiv.passwordpolicy/)

### Installation

1.  Clone this repository, then change your working directory.

    ```shell
    git clone git@github.com:interaktivgmbh/interaktiv.passwordpolicy.git
    cd interaktiv.passwordpolicy
    ```

2.  Install this code base.

    ```shell
    make install
    ```

3.  Run the tests and the code checks.

    ```shell
    make test
    make check
    ```

## License

The project is licensed under GPLv2.
