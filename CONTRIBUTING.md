# Contributing

Thanks for adding to the library. Every query here is meant to be safe to run by someone who has never seen it before, so a contribution needs three things: the standard template, a real test against Huntress SIEM, and nothing that identifies a client.

Read [Read this first](README.md#read-this-first) in the README before you write a query. Most broken queries come from the traps listed there.

## Template

One query per file, in the folder for its data source. File names are lowercase kebab-case, for example `Fortigate/admin-login-from-external-ip.yaml`. Keep the fields in this order.

```yaml
title: Example Failed Sign-Ins from One IP
id: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d        # generate a new UUIDv4 for every query
status: Production
description: >
  One or two sentences on what the query finds and why it matters.
author: your-github-handle
date: 2026/10/21
modified: 2026/10/21
references:
  - "https://support.huntress.io/hc/en-us/articles/30113222043155-Searching-Logs-ESQL"
tags:
  - attack.t1110
  - attack.credential_access
  - microsoft.entra.id
logsource:
  language: ESQL
  platform: Huntress SIEM
  provider: "ITDR"                               # exact event.provider value
picker: >
  Any window works: Huntress reads the whole picker range, newest first, in 4-hour steps.
  Wide ranges take longer. Results are complete only once the grid shows Done.
placeholders:
  - "<ip>: the IPv4 or IPv6 address to look up, for example 203.0.113.10"
query: >
  from logs
  | WHERE
      event.provider=="ITDR"
      AND TO_LOWER(itdr.Operation)=="userloginfailed"
      AND (source.ip=="<ip>" OR itdr.ClientIP=="<ip>" OR itdr.ActorIpAddress=="<ip>")
  | STATS
      events = COUNT(*)
      BY itdr.UserId
  | SORT
      events DESC
expected_result: >
  What a normal day returns, with a rough volume if you know it.
outcomes:
  rows: >
    What a row means and what to do next.
  empty: >
    What an empty result means, and when it is NOT clean (a logging or audit setting
    the events need, a rare event, a placeholder typo).
  error: >
    Check the query was pasted whole and every placeholder was replaced. Huntress
    reports parser errors as Not all query parsed or Invalid operator.
known_limits: >
  What the query can't see: fields that can be blank, casing, rows whose @timestamp falls outside
  the picker window.
analyst_notes: >
  Background an analyst needs: what the event codes mean, how to investigate a hit.
```

Field rules:

- `logsource.provider` is the exact `event.provider` value. Use a YAML list when a query spans providers, or `any` for a query that covers every provider. The values are listed in the README's [Field reference](README.md#field-reference).
- `placeholders` lists every `<name>` used in the query, as `"<name>: what to put here, example"`. Use `[]` when the query has none. Never leave a real value in a query as a sample.
- Use a literal block (`analyst_notes: |`) when the notes are a list, so line breaks are kept.

## Testing a query

A query goes in only after it has returned a known result in Huntress SIEM.

1. **Pick a window that contains a known event** and write down the window you used. Wide windows are fine; they just take longer.
2. **Find a known row first.** Before trusting an empty result, find a real event that the query should match, using a broader search over the same window.
3. **Add one condition at a time.** Run the query after each new filter or operator and confirm the known row still comes back. Never `OR` together conditions you haven't tested; a hit can't tell you which one worked and a miss can't tell you which one failed.
4. **Prove empty means empty.** A query that has never returned a row can't call an empty result clean. If the event is rare, say so in `outcomes.empty` and name any setting it depends on.
5. **Check the traps.** No `limit`. `*` not `%` in `LIKE`. No `message` searches. Exact provider string and field names, which are case sensitive.
6. **Wait for Done** before reading the result. For a raw search, scroll until the grid says Done, since older rows load only as you scroll. Take field names from a row's details, not from the grid headers.

If something behaves differently from the README, open an issue with the query, the picker setting and what you saw. Leave out any client data.

## Style

- No em or en dashes anywhere. Use a comma, colon, parentheses or a new sentence.
- Plain, direct wording. Say what the query finds and what to do with a result.
- Tags follow the [tagging convention](README.md#tagging-convention).
- Example values must be invented, never copied from real logs: `203.0.113.10` (a documentation IP range), `user@example.com`, `pc01.corp.example.com`, `a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d`.
- Published IOCs from a public source are fine in an IOC sweep query; cite the source in `references`.

## Pull request checklist

- [ ] One query per file, lowercase kebab-case file name, in the right folder.
- [ ] Every template field is present and in order, with a new UUIDv4 `id`.
- [ ] `logsource.provider` is an exact `event.provider` value.
- [ ] Every `<placeholder>` in the query is listed under `placeholders`.
- [ ] No `limit`, no `%` in `LIKE`, no search on `message`.
- [ ] Tested in Huntress SIEM against a known row, read after Done; the PR description gives the window and what came back (counts only).
- [ ] `outcomes.empty` says when empty isn't clean.
- [ ] No client names, company names, real users, emails, hostnames, IPs, tenant IDs, session IDs or alert titles anywhere, including examples.
- [ ] No em or en dashes.
- [ ] If the query is in a new folder or the PR adds any file other than a query, say so in the PR so a maintainer can approve the new path.
