# logscrub

Redact secrets and PII from text **before** you paste it into an LLM, drop it in a
GitHub issue, or share a log in chat.

We've all done it: copy a stack trace or a `.env` into ChatGPT to debug something,
and quietly leak an API key in the process. `logscrub` is a tiny, dependency-free
filter that catches the usual suspects and replaces them with clear placeholders.

```text
$ cat app.log | logscrub --stats
logscrub: redacted 5 item(s): openai_key=1, secret_assignment=1, email=1, ip=1, credit_card=1
ERROR auth failed
OPENAI_KEY=[REDACTED:openai_key]
user [REDACTED:email] from [REDACTED:ip]
password=[REDACTED:secret_assignment]
card [REDACTED:credit_card]
```

## Install

```bash
pip install logscrub        # once published to PyPI
# or, from source:
pip install .
```

## Use it as a CLI

```bash
cat app.log | logscrub                 # stdin -> stdout
logscrub app.log -o clean.log          # file -> file
logscrub app.log --stats               # also print a summary to stderr
cat app.log | logscrub --keep email,ip # leave emails and IPs alone
```

## Use it as a library

```python
from logscrub import scrub

result = scrub('OPENAI_KEY=sk-proj-...  contact me@example.com')
print(result.text)        # 'OPENAI_KEY=[REDACTED:openai_key]  contact [REDACTED:email]'
print(result.findings)    # Counter({'openai_key': 1, 'email': 1})
print(result.total)       # 2
```

## What it catches

| Category | Examples |
|---|---|
| API keys / tokens | OpenAI (`sk-…`), GitHub (`ghp_…`), AWS (`AKIA…`), Google (`AIza…`), Slack (`xox…`), Stripe (`sk_live_…`), Twilio (`SK…`), SendGrid (`SG.…`) |
| Auth | `Bearer …`, JWTs (`eyJ….….…`) |
| Keys | `-----BEGIN … PRIVATE KEY-----` blocks |
| Named values | `password = …`, `api_key: …`, `client_secret=…` (value redacted, key kept) |
| PII | emails, IPv4 addresses, credit-card numbers |

To keep false positives low:

- **Credit cards** are only redacted if they pass a [Luhn](https://en.wikipedia.org/wiki/Luhn_algorithm) check.
- **IPv4** must have valid octets (so `999.1.1.1` or a version string is left alone).

It's a pragmatic filter, not a security guarantee — review anything sensitive before
sharing. Adding a detector is one line in `logscrub/patterns.py`; PRs welcome.

## Tests

```bash
pip install pytest && pytest
```

## License

[MIT](LICENSE) © Tianwater
