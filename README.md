# huntress_siem_library

Tested ES|QL queries for Huntress Managed SIEM, one YAML file per query. Each file tells you how to set the time picker, what to replace before running, what a normal result looks like, and what an empty result does and doesn't mean.

Some queries aren't security detections. They're there for troubleshooting log ingestion and for finding field names.

## How to use a query

1. Open the query's `.yaml` file and copy everything under `query:` into the Huntress SIEM search box (ES|QL mode).
2. Set the time picker the way the file's `picker` says. For almost every query that's one UTC day (see [Read this first](#read-this-first)).
3. Replace every value listed under `placeholders`, for example `<ip>`. Leaving a placeholder in returns nothing, and nothing looks like a clean result.
4. Read the result against `outcomes`: what rows mean, what an empty result means (and when it isn't clean), and what an error usually means.
5. Check `known_limits` before you treat a result as complete.

## Read this first

Huntress SIEM runs a restricted ES|QL. These rules come from testing against live tenants. Where Huntress's own docs say something different, the tested behavior is what's listed here.

| Rule | Detail |
|---|---|
| Source is `from logs` | `FROM logs*` and `FROM logs-*` fail with "Not all query parsed". |
| One UTC day per search | A search reads only the last UTC calendar day of the picker window, `stats` included. A 7 day picker is a 1 day search. Run longer hunts one day at a time. |
| Never use `limit` | `limit` makes Huntress compute on a reduced slice of the data. A `stats` with `limit 200` counted 8,942 events where the real count was 82,013, and a raw search with `limit 20` returned 0 of 8 matching rows. The results grid already pages rows. |
| `LIKE` uses `*` | `%` is a literal character, so `LIKE "%admin%"` matches nothing. Huntress's ES\|QL guide shows `%`; it's wrong. |
| `==` is case sensitive | So are field names (`winlog.event_data.Ipaddress` and `IpAddress` are different fields). Use `TO_LOWER(field) == "value"` for exact case-insensitive matches and `CONTAINS(field, "text")` for case-insensitive partial matches. The same operation can appear with different casing, for example `UserLoggedIn` and `UserLoggedin`. |
| `message` is a summary | It holds one line like "User successfully logged in." and never contains IPs, users or IDs. Don't search it for IOCs. Use `CONTAINS(event.original, "text")` to search the raw event. |
| Watch `WHERE` after `STATS` | A `WHERE` after a `STATS` that includes `MIN(@timestamp)` or `MAX(@timestamp)` returns no rows. Filter on counts in a query without the timestamp aggregations. |
| Wait for Done | Results stream in while the search runs ("Aggregating results..."). Read them once the grid says Done. |
| Headers aren't field names | The grid relabels some columns (for example `itdr.ClientIP` shows as `source.ip`) and always adds Organization. Take field names from a row's details. |
| Missing fields count as null | `COUNT(field)` counts only rows where the field exists (Huntress's docs say missing fields read as empty values; testing showed otherwise). Empty strings still count. |
| Functions confirmed | `TO_LOWER`, `CONTAINS`, `CIDR_MATCH`, `IN (...)`, `COUNT`, `count_distinct`, `MIN`, `MAX`, `SORT` after `STATS`. `TO_STRING` fails. Huntress documents `EVAL`, `DROP`, `RENAME` and `MV_EXPAND`; they're untested here. |

**Picker settings for one UTC day** (the picker is in Eastern time):

| Period | Start | End |
|---|---|---|
| EDT (March to November) | 20:00 the day before | 19:59 |
| EST (November to March) | 19:00 the day before | 18:59 |

A picker end time in the future returns nothing. For the current day, end the window at the current time.

Retention is 30 days hot and 1 year cold by default. Huntress offers a 90 day hot / 7 year cold add-on.

## Field reference

The exact `event.provider` value for each source, the fields the queries use, and the traps found in testing.

### ITDR (Microsoft 365 and Entra unified audit log)

| Item | Detail |
|---|---|
| Provider | `ITDR` |
| Who and what | `itdr.UserId`, `itdr.UserKey` (stable when UserId is blank), `itdr.Operation`, `itdr.ObjectId` |
| Where from | `itdr.ClientIP`, `itdr.ActorIpAddress`, `source.ip` (check all three; app-only directory changes carry no IP) |
| Result | `itdr.LogonError`, `itdr.ErrorNumber`. `itdr.ResultStatus` reads Success even on failed sign-ins, so don't use it. |
| Session and device | `session.id`, `itdr.DeviceProperties.OS`, `.BrowserType`, `.IsCompliant` (sign-in records only) |
| Raw details | `itdr.ExtendedProperties.Value` holds result detail, user agent and request type as one comma-joined string. Device code sign-ins carry `Cmsi:Cmsi` here. |
| Traps | Operation names end with a period (`Enable Strong Authentication.`); match them with `LIKE` or `TO_LOWER(...) LIKE`. Anonymous Microsoft Forms responses log IP `0.0.0.0`. App directory actions show `itdr.UserId` as `ServicePrincipal_<guid>`, the object ID, not the app ID. |

### Cisco Duo

| Item | Detail |
|---|---|
| Provider | `Duo` |
| Authentication records | `duo.email`, `duo.result` (`success`, `denied`, `fraud`), `duo.reason` (for example `user_approved`, `no_response`, `bypass_user`), `duo.factor` (for example `duo_push`, `verified_duo_push`, `sms_passcode`), `duo.application.name`, `duo.access_device.ip`, `duo.access_device.location.*` |
| Telephony records | `duo.context`, `duo.phone`, `duo.type` (`sms`, `phone`) |
| Traps | All values are lowercase. There's no `allow` result. A bypass code login is a `success` with reason `bypass_user`. |

### FortiGate

| Item | Detail |
|---|---|
| Provider | `Syslog-Fortigate` (lowercase g; Huntress's FortiGate doc says `Syslog-FortiGate`, which matches nothing) |
| Common fields | `event.code`, `fortigate.duser`, `fortigate.src`, `fortigate.dst`, `fortigate.reason`, `fortigate.outcome`, `fortigate.FTNTFGTmethod`, `fortigate.FTNTFGTprofile`, `fortigate.FTNTFGTtunnelid`, `fortigate.FTNTFGTtunnelip` |
| Traps | `event.name` is only a category label like `event:vpn`. On SSL-VPN events `fortigate.src` is empty and the remote IP is in `source.ip` and `fortigate.dst`. `count_distinct(fortigate.duser)` empties the whole result. Raw message text is in `event.original` (CEF `msg=`). |
| Codes used | 32001/32002 admin login success/failure, 39426 SSL-VPN login failure, 39424/39947/39948 SSL-VPN tunnel up/up/down, 43008/43009/43010 local auth success/failure/lockout. 37130 is an IPsec phase 2 error, not an SSL-VPN failure. |

### SonicWall

| Item | Detail |
|---|---|
| Provider | `Syslog-SonicWall` |
| Common fields | `event.code` (equals the SonicWall message ID `sonicwall.m`), `sonicwall.msg`, `sonicwall.usr`, `sonicwall.sn` (serial), `sonicwall.src`, `sonicwall.dst`, `sonicwall.note`, `source.ip`, `host.ip` |
| Traps | `host.hostname` is never populated; identify the firewall by `sonicwall.sn` or `host.ip`. `sonicwall.sess` doesn't exist under that name. Login and logout events only arrive when the firewall's syslog includes the Authentication Access category. |

### Meraki MX

| Item | Detail |
|---|---|
| Provider | `Syslog-Meraki` (MX syslog). The separate Meraki cloud API integration uses `MerakiCloud`. |
| Common fields | `meraki.event_type` (the Meraki syslog category, for example `events`), `meraki.event_description` (for example `content_filtering_block`, `authentication`, `dhcp lease`), `host.hostname`, `host.ip` |
| Traps | `security_event` (IDS and malware scan results) is only sent when the MX syslog server has the Security events role enabled. |

### SentinelOne

| Item | Detail |
|---|---|
| Provider | `Syslog-SentinelOne` |
| Common fields | `event.code`, `message`, `sentinelone.*` (for example `sentinelone.eventDesc`, `sentinelone.activityType`, `sentinelone.deviceHostName`), `file.hash.sha256`, `file.path`, `process.command_line` |
| Traps | Only alerts and threat activity are ingested, not endpoint telemetry. Common codes: 19 new active threat, 2001 kill, 2004 quarantine, 2009 quarantine failed, 2028 incident status changed, 2030 analyst verdict changed. |

### Windows event logs

| Item | Detail |
|---|---|
| Providers | `Microsoft-Windows-Security-Auditing`, `Microsoft-Windows-DNS-Client`, `Microsoft-Windows-HttpService`. Service installs (7045) come from `Service Control Manager`. |
| Common fields | `event.code` (numeric; quoted and unquoted both work), `host.hostname`, `user.name`, `winlog.event_data.*` (string values) |
| Traps | Field names are case sensitive (`winlog.event_data.Ipaddress` on DNS-Client). Many events only exist when the matching audit policy is on; each query's `outcomes.empty` names the setting. |

## Find a query

### By data source

**ITDR**

| Query | Use it to |
|---|---|
| [entra-find-all-events-in-a-session.yaml](ITDR/entra-find-all-events-in-a-session.yaml) | See every record in one browser session, across accounts |
| [entra-mfa-disabled.yaml](ITDR/entra-mfa-disabled.yaml) | Find per-user MFA being turned off |
| [entra-mfa-enabled.yaml](ITDR/entra-mfa-enabled.yaml) | Find per-user MFA being turned on |
| [entra-user-activity-by-actor-ip-address.yaml](ITDR/entra-user-activity-by-actor-ip-address.yaml) | Summarize everything one IP did |
| [entra-user-login-blocked-by-conditional-access.yaml](ITDR/entra-user-login-blocked-by-conditional-access.yaml) | List sign-ins Conditional Access blocked |
| [entra-user-login-failures.yaml](ITDR/entra-user-login-failures.yaml) | List failed sign-ins |
| [entra-user-login-invalid-username-or-password.yaml](ITDR/entra-user-login-invalid-username-or-password.yaml) | List wrong-password failures |
| [entra-user-login-strong-auth-enrollment-required.yaml](ITDR/entra-user-login-strong-auth-enrollment-required.yaml) | List sign-ins interrupted for MFA |
| [impossible-travel-signin.yaml](ITDR/impossible-travel-signin.yaml) | Rank accounts by distinct sign-in IPs in a day |
| [oauth-device-code-flow-authentication.yaml](ITDR/oauth-device-code-flow-authentication.yaml) | Find device code sign-ins |

**Cisco Duo**

| Query | Use it to |
|---|---|
| [all-logs-by-event-provider.yaml](Cisco%20Duo/all-logs-by-event-provider.yaml) | Check Duo logs are arriving and see the fields |
| [authorization-failure.yaml](Cisco%20Duo/authorization-failure.yaml) | List denied authentications |
| [authorization-success.yaml](Cisco%20Duo/authorization-success.yaml) | List successful authentications |
| [duo-authentication-failure-spike.yaml](Cisco%20Duo/duo-authentication-failure-spike.yaml) | Find users with five or more failures |
| [duo-type-sms.yaml](Cisco%20Duo/duo-type-sms.yaml) | Find SMS passcodes sent |
| [mfa-push-fatigue-deny-then-allow.yaml](Cisco%20Duo/mfa-push-fatigue-deny-then-allow.yaml) | Spot denied pushes followed by an approval |

**FortiGate**

| Query | Use it to |
|---|---|
| [admin-login-from-external-ip.yaml](Fortigate/admin-login-from-external-ip.yaml) | Find successful admin logins from public IPs |
| [admin-logins-on-any-interface.yaml](Fortigate/admin-logins-on-any-interface.yaml) | List admin login successes and failures |
| [all-logs-by-hostname.yaml](Fortigate/all-logs-by-hostname.yaml) | Check FortiGate logs are arriving and see the fields |
| [failed-sslvpn-logins.yaml](Fortigate/failed-sslvpn-logins.yaml) | List failed SSL-VPN logins |
| [firmware-version-change.yaml](Fortigate/firmware-version-change.yaml) | Find firmware upgrades, downgrades and restores |
| [local-logins-against-firewall.yaml](Fortigate/local-logins-against-firewall.yaml) | List firewall-local authentication |
| [ssl-vpn-auth-failure-spike.yaml](Fortigate/ssl-vpn-auth-failure-spike.yaml) | Rank source IPs by SSL-VPN failures |
| [sslvpn-tunnel-info.yaml](Fortigate/sslvpn-tunnel-info.yaml) | List SSL-VPN tunnels up and down |

**SonicWall**

| Query | Use it to |
|---|---|
| [admin-logout.yaml](Sonicwall/admin-logout.yaml) | List admin logouts |
| [admin-vpn-login.yaml](Sonicwall/admin-vpn-login.yaml) | List admin VPN logins |
| [admin-wan-login.yaml](Sonicwall/admin-wan-login.yaml) | List admin WAN logins |
| [all-attack-activity.yaml](Sonicwall/all-attack-activity.yaml) | List attacks the firewall dropped (scans, floods, spoofing) |
| [all-logs-by-hostname.yaml](Sonicwall/all-logs-by-hostname.yaml) | Check SonicWall logs are arriving and see the fields |
| [failed-logins.yaml](Sonicwall/failed-logins.yaml) | List failed logins |
| [sonicwall-vpn-ioc-login-by-ip.yaml](Sonicwall/sonicwall-vpn-ioc-login-by-ip.yaml) | Sweep for published SonicWall VPN attacker IPs |
| [successful-sslvpn-user-login.yaml](Sonicwall/successful-sslvpn-user-login.yaml) | List successful SSL-VPN logins |
| [user-logout.yaml](Sonicwall/user-logout.yaml) | List user logouts |
| [user-vpn-login.yaml](Sonicwall/user-vpn-login.yaml) | List user VPN logins |
| [user-wan-login.yaml](Sonicwall/user-wan-login.yaml) | List user WAN logins |

**Meraki and SentinelOne**

| Query | Use it to |
|---|---|
| [Meraki: all-logs-by-hostname.yaml](Meraki/all-logs-by-hostname.yaml) | Check Meraki logs are arriving and see the fields |
| [Meraki: all-security-alerts.yaml](Meraki/all-security-alerts.yaml) | List IDS and malware scan events |
| [SentinelOne: all-logs-by-event-provider.yaml](SentinelOne/all-logs-by-event-provider.yaml) | List SentinelOne alerts and threat activity |

**Windows event logs**

| Query | Use it to |
|---|---|
| [account-logon-failed.yaml](Windows%20Event/account-logon-failed.yaml) | List failed logons (4625) |
| [account-management-events.yaml](Windows%20Event/account-management-events.yaml) | List accounts created, enabled, disabled, deleted |
| [dns-client-event-provider.yaml](Windows%20Event/dns-client-event-provider.yaml) | Troubleshoot DNS client problems |
| [event-provider-by-hostname.yaml](Windows%20Event/event-provider-by-hostname.yaml) | See all Security events from one host |
| [events-from-a-specific-process.yaml](Windows%20Event/events-from-a-specific-process.yaml) | See Security events naming one process |
| [gpo-changes.yaml](Windows%20Event/gpo-changes.yaml) | List directory and Group Policy object changes |
| [httpservice-event-provider.yaml](Windows%20Event/httpservice-event-provider.yaml) | List HTTP.sys configuration changes |
| [kerberoasting-rc4-service-ticket-request.yaml](Windows%20Event/kerberoasting-rc4-service-ticket-request.yaml) | Find RC4 service tickets (Kerberoasting) |
| [key-storage-provider.yaml](Windows%20Event/key-storage-provider.yaml) | List key storage operations |
| [local-user-account-created.yaml](Windows%20Event/local-user-account-created.yaml) | List new user accounts (4720) |
| [overpass-the-hash-rc4-tgt-request.yaml](Windows%20Event/overpass-the-hash-rc4-tgt-request.yaml) | Find RC4 TGT requests (overpass-the-hash) |
| [pass-the-hash-ntlm-network-logon-zero-key.yaml](Windows%20Event/pass-the-hash-ntlm-network-logon-zero-key.yaml) | Find NTLM network logons with key length 0 |
| [privileged-group-membership-change.yaml](Windows%20Event/privileged-group-membership-change.yaml) | List members added to security groups |
| [registry-key-modification.yaml](Windows%20Event/registry-key-modification.yaml) | Find Run and RunOnce key changes |
| [scheduled-task-creation.yaml](Windows%20Event/scheduled-task-creation.yaml) | List new scheduled tasks |
| [sonicwall-vpn-ioc-driver-installed-by-attacker.yaml](Windows%20Event/sonicwall-vpn-ioc-driver-installed-by-attacker.yaml) | Sweep for published attacker drivers |
| [sonicwall-vpn-ioc-ransomware-executables.yaml](Windows%20Event/sonicwall-vpn-ioc-ransomware-executables.yaml) | Sweep for published attacker tools |
| [sonicwall-vpn-ioc-user-created-by-attacker.yaml](Windows%20Event/sonicwall-vpn-ioc-user-created-by-attacker.yaml) | Sweep for published attacker account names |
| [username-is-administrator.yaml](Windows%20Event/username-is-administrator.yaml) | See events for administrator accounts |

### By scenario

| You're looking at | Start with |
|---|---|
| A suspicious Microsoft 365 sign-in | [entra-user-activity-by-actor-ip-address.yaml](ITDR/entra-user-activity-by-actor-ip-address.yaml), then [entra-find-all-events-in-a-session.yaml](ITDR/entra-find-all-events-in-a-session.yaml) |
| A possible account takeover | [impossible-travel-signin.yaml](ITDR/impossible-travel-signin.yaml), [entra-mfa-disabled.yaml](ITDR/entra-mfa-disabled.yaml), [entra-user-login-failures.yaml](ITDR/entra-user-login-failures.yaml) |
| Device code phishing | [oauth-device-code-flow-authentication.yaml](ITDR/oauth-device-code-flow-authentication.yaml) |
| MFA fatigue | [mfa-push-fatigue-deny-then-allow.yaml](Cisco%20Duo/mfa-push-fatigue-deny-then-allow.yaml), [duo-authentication-failure-spike.yaml](Cisco%20Duo/duo-authentication-failure-spike.yaml) |
| Password spraying or brute force | [entra-user-login-invalid-username-or-password.yaml](ITDR/entra-user-login-invalid-username-or-password.yaml), [ssl-vpn-auth-failure-spike.yaml](Fortigate/ssl-vpn-auth-failure-spike.yaml), [account-logon-failed.yaml](Windows%20Event/account-logon-failed.yaml) |
| An exposed firewall admin interface | [admin-logins-on-any-interface.yaml](Fortigate/admin-logins-on-any-interface.yaml), [admin-login-from-external-ip.yaml](Fortigate/admin-login-from-external-ip.yaml), [admin-wan-login.yaml](Sonicwall/admin-wan-login.yaml) |
| A firewall firmware change | [firmware-version-change.yaml](Fortigate/firmware-version-change.yaml) |
| A new account or privilege change | [account-management-events.yaml](Windows%20Event/account-management-events.yaml), [privileged-group-membership-change.yaml](Windows%20Event/privileged-group-membership-change.yaml) |
| Persistence on a Windows host | [scheduled-task-creation.yaml](Windows%20Event/scheduled-task-creation.yaml), [registry-key-modification.yaml](Windows%20Event/registry-key-modification.yaml) |
| Kerberos or NTLM credential abuse | [kerberoasting-rc4-service-ticket-request.yaml](Windows%20Event/kerberoasting-rc4-service-ticket-request.yaml), [overpass-the-hash-rc4-tgt-request.yaml](Windows%20Event/overpass-the-hash-rc4-tgt-request.yaml), [pass-the-hash-ntlm-network-logon-zero-key.yaml](Windows%20Event/pass-the-hash-ntlm-network-logon-zero-key.yaml) |
| An IOC sweep | [entra-user-activity-by-actor-ip-address.yaml](ITDR/entra-user-activity-by-actor-ip-address.yaml), [sonicwall-vpn-ioc-login-by-ip.yaml](Sonicwall/sonicwall-vpn-ioc-login-by-ip.yaml) |
| Whether logs are arriving | The "all logs" query for each source above |

## Huntress documentation

Huntress's docs are useful background, but some examples in them don't work as written (see [Read this first](#read-this-first)). Test before you trust an example.

| Doc | Covers |
|---|---|
| [Searching Logs - ESQL](https://support.huntress.io/hc/en-us/articles/30113222043155-Searching-Logs-ESQL) | Supported commands and functions |
| [Searching Logs - Query Builder](https://support.huntress.io/hc/en-us/articles/47939695233299) | The no-code query builder |
| [Using AI Search in Huntress SIEM](https://support.huntress.io/hc/en-us/articles/52480686631059) | Plain English to ES\|QL |
| [Managed SIEM Best Practices](https://support.huntress.io/hc/en-us/articles/52953363398803) | Saved and scheduled queries |
| [Managed SIEM FAQ](https://support.huntress.io/hc/en-us/articles/34486430254611) | General questions |
| [Billing and Retention](https://support.huntress.io/hc/en-us/articles/41624615133715) | Retention tiers |
| [Collecting Syslog Sources](https://support.huntress.io/hc/en-us/articles/32270678960531) | Syslog setup and timestamps |
| [Starter Queries - Azure AD, Exchange, SharePoint, OneDrive, Teams](https://support.huntress.io/hc/en-us/articles/36700032460691) | ITDR fields |
| [ITDR documentation](https://support.huntress.io/hc/en-us/categories/19906075516051) | Huntress ITDR |
| [SIEM: API - Cisco Duo](https://support.huntress.io/hc/en-us/articles/36516946793107) | Duo integration |
| [SIEM: Syslog - Fortinet FortiGate](https://support.huntress.io/hc/en-us/articles/33937884048147) | FortiGate integration |
| [SIEM: Syslog - SonicWall Firewall](https://support.huntress.io/hc/en-us/articles/33940022013843) | SonicWall integration |
| [SIEM: Syslog - Cisco Meraki MX](https://support.huntress.io/hc/en-us/articles/38958950569107) | Meraki MX integration |
| [SIEM: API - SentinelOne Audit Logs](https://support.huntress.io/hc/en-us/articles/41838176250259) | SentinelOne integration |
| [Collecting Windows Event Logs](https://support.huntress.io/hc/en-us/articles/36005287194259) | Windows event log collection |
| [Release Notes](https://support.huntress.io/hc/en-us/articles/19223729361939) | Product changes |

Elastic's general ES|QL reference: [ES|QL syntax](https://www.elastic.co/docs/reference/query-languages/esql/esql-syntax). Huntress supports a subset of it.

## Tagging convention

Queries use [MITRE ATT&CK](https://attack.mitre.org/) tags where a technique cleanly applies.

- Tactic: `attack.<tactic_name>`, for example `attack.credential_access`, `attack.persistence`
- Technique: `attack.t<id>` or `attack.t<id>.<sub>`, for example `attack.t1078`, `attack.t1558.003`
- Log source: one tag naming the data source, for example `windows.event`, `cisco.duo`, `fortigate`, `microsoft.entra.id`, `sonicwall`, `meraki`, `sentinelone`

Utility and starter queries that don't map to a technique carry only the log source tag.

| Tag | Tactic | ID |
|---|---|---|
| `attack.initial_access` | Initial Access | TA0001 |
| `attack.execution` | Execution | TA0002 |
| `attack.persistence` | Persistence | TA0003 |
| `attack.privilege_escalation` | Privilege Escalation | TA0004 |
| `attack.defense_evasion` | Defense Evasion | TA0005 |
| `attack.credential_access` | Credential Access | TA0006 |
| `attack.discovery` | Discovery | TA0007 |
| `attack.lateral_movement` | Lateral Movement | TA0008 |
| `attack.impact` | Impact | TA0040 |

## Contributing

New queries and fixes are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the template, how to test a query, and the pull request checklist.
