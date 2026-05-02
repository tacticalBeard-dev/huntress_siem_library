# huntress_siem_library

Repository for sharing and source control for Huntress SIEM queries.

## Project Description

<p>Some of these queries are not directly related to security but may be useful for troubleshooting other issues.</p>

<p>The formatting for these queries is designed to improve readability especially for longer queries and is not optimized for performance.</p>

## Key Components

*   <a href="url">https://www.elastic.co/docs/explore-analyze/query-filter/languages</a>
*   <a href="url">https://www.elastic.co/docs/reference/query-languages/esql/esql-syntax</a>
*   <a href="url">https://support.huntress.io/hc/en-us/articles/30113222043155-Huntress-Managed-SIEM-Log-Search-Guide</a>

## Key Features

1.  Standardized format for creating and sharing queries.
2.  Templates for building and modifying queries.
3.  Documentation for original references.

## Tech Stack

*   ES|QL (Elastic Stack Query Language)
*   Huntress SIEM

## Tagging Convention

All queries use [MITRE ATT&CK](https://attack.mitre.org/) framework tags where a technique cleanly applies.

**Tag format:**
- Tactic: `attack.<tactic_name>` — e.g., `attack.credential_access`, `attack.persistence`
- Technique: `attack.t<id>` or `attack.t<id>.<sub>` — e.g., `attack.t1078`, `attack.t1558.003`
- Log source: one tag identifying the data source — e.g., `windows.event`, `cisco.duo`, `fortigate`, `microsoft.entra.id`, `sonicwall`, `meraki`, `sentinelone`

Utility and starter queries that do not map to a specific ATT&CK technique carry only the log source tag.

**ATT&CK Tactic reference:**

| Tag | Tactic | ID |
|-----|--------|----|
| `attack.initial_access` | Initial Access | TA0001 |
| `attack.execution` | Execution | TA0002 |
| `attack.persistence` | Persistence | TA0003 |
| `attack.privilege_escalation` | Privilege Escalation | TA0004 |
| `attack.defense_evasion` | Defense Evasion | TA0005 |
| `attack.credential_access` | Credential Access | TA0006 |
| `attack.discovery` | Discovery | TA0007 |
| `attack.lateral_movement` | Lateral Movement | TA0008 |
| `attack.impact` | Impact | TA0040 |

## YAML format
```
title: 
id: 
status: 
description: >
author: 
date: 
modified: 
references:
  - 
tags:
  - 
logsource:
  language: 
  platform: 
  type: 
analyst_notes: >
query: >
```
