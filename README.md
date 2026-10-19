# Prompt Proxy UI mock-ups

Clickable mock-ups of the two web pages of the **Prompt Proxy System**, an OpenAI-compatible gateway that masks
personal data and secrets and runs guardrail checks on prompts and replies.

**Open the mock-ups: https://Aekkritktpl.github.io/prompt-proxy-mockups/**

> **Mock-up only.** There is no server behind these pages. Every number, request and result is sample data,
> nothing you type is sent anywhere, and changes you make are kept only in your own browser.

## What's here

| Page | Link | What to look at |
|---|---|---|
| **Pipeline Inspector** | [ui/](https://Aekkritktpl.github.io/prompt-proxy-mockups/ui/) | Type a prompt, or pick one of 42 examples, and press **Run** to see what each of the 10 pipeline steps receives and returns. Examples show their documented result (pass, block or mask). |
| **Admin dashboard** | [admin/](https://Aekkritktpl.github.io/prompt-proxy-mockups/admin/) | Traffic overview, live requests and request logs, the **pipeline board** (Guardrails › Pipeline) for switching steps on/off and changing their settings, rules, users and API keys, models, alerts and the audit log. |

## Giving feedback

1. Tick **Show component names** (top of the Inspector, bottom-right of the dashboard), or add `?labels` to the address.
2. Each part of the page gets an outline and its name, for example
   `TopUsers · src/pages/dashboard/TopUsers.tsx` or `Masking panel (#mask-d)`.
3. Mention that name in your feedback, or send a screenshot with the names visible.

## Good to know

- **Your changes are private to your browser.** Pipeline settings and the audit log survive a reload; new API keys,
  alerts and user changes reset when you reload. Nobody else sees them.
- **On the pipeline board,** settings marked **not used yet** exist in the real `config.json` but the backend doesn't
  read them yet.
- **Seeing an old version?** Hard-refresh with ⌘ + Shift + R (Ctrl + Shift + R on Windows).
- **Links use `#/`** in the dashboard (for example `admin/#/guardrails/pipeline`) because GitHub Pages can't route
  other paths. The real app uses normal paths.

## About this repository

This repository only holds the **built** pages. The source code is in a separate, private project, and
`scripts/publish-mockups.sh` there replaces this repository's contents on each publish, so **don't edit files here**.
Changes belong in the source project.

Published 2026-10-19 18:27 UTC from source commit `6fc857f+uncommitted`.
