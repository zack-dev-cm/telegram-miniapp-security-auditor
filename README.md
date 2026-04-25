# Telegram Mini App Security Auditor

Audit Telegram Mini App projects before connecting bot tokens, BotFather, or public channels.

This repo packages a Codex/OpenClaw skill plus a deterministic static auditor. It is intended as the first gate in a Telegram Mini App shipping workflow: audit first, then browser QA, then launch.

## What It Checks

- Telegram `initData` server-side validation signals
- committed Telegram bot tokens and token-like literals
- admin endpoints without server-side guards
- wildcard CORS and credential risk
- unsafe `innerHTML` usage
- frame headers that can break Telegram embedding
- contact/PII/token rejection on request forms
- health-check and HTTPS launch-readiness notes
- live Bot API actions without dry-run or review gates

## Quick Start

```bash
python3 skill/telegram-miniapp-security-auditor/scripts/audit_tma.py \
  /path/to/telegram-miniapp-project \
  --out-dir /tmp/tma-audit
```

Outputs:

- `/tmp/tma-audit/tma_security_audit.json`
- `/tmp/tma-audit/tma_security_audit.md`

Decision meanings:

- `PASS`: no blocking or review-triggering evidence found by this static pass.
- `REVIEW`: launch only after a human verifies the listed risks.
- `BLOCK`: do not launch or connect production bot tokens until fixed.

## Codex Skill

The skill lives at:

```text
skill/telegram-miniapp-security-auditor/
```

Install locally for Codex by copying that folder into:

```text
~/.codex/skills/telegram-miniapp-security-auditor/
```

OpenClaw users can install the same folder into a workspace skills directory.

## Example

Audit a frontend-only Mini App folder:

```bash
python3 skill/telegram-miniapp-security-auditor/scripts/audit_tma.py ./miniapp --out-dir /tmp/tma-audit
```

If the backend validator is outside that folder, the result should usually be `BLOCK`; audit the full project root before production launch.

## Limitations

This is a static heuristic audit. It does not prove runtime safety, BotFather configuration, browser rendering, or Telegram production launch. Treat token-like findings as leaked credentials until proven otherwise.

## License

MIT No Attribution (MIT-0)
