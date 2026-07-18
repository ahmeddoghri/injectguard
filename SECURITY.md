# Security Policy

## Supported versions

This project is pre-1.0. Security fixes land on `main`; track the latest commit.

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/ahmeddoghri/injectguard/security/advisories/new)
or email the maintainer. Include a description of the issue and its impact,
steps to reproduce (a minimal proof-of-concept helps), and any suggested fix.

You can expect an acknowledgement within a few days. Once a fix is out you will
be credited unless you would rather stay anonymous.

## Please read this before you deploy it

injectguard is a first line of defense, not a security boundary. It is a
transparent pattern detector. It stops the common copy-paste injection and
jailbreak attempts, and it is easy to audit, but a determined attacker who
rephrases their payload will get past it. Regex cannot win an arms race against
natural language.

Treat it as one layer. The real defense against prompt injection is still
architectural: keep untrusted content out of the same trust context as your
instructions, do not give an agent tools it should not use on untrusted input,
and confirm high-impact actions with a human. injectguard makes the cheap
attacks expensive; it does not make you safe on its own.

If you find a bypass, that is genuinely useful. Please report it (or better,
send a pull request that adds it to the red-team corpus).
