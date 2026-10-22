# huntress_siem_library

Tested ES|QL queries for Huntress Managed SIEM, one YAML file per query. Each file tells you how to set the time picker, what to replace before running, what a normal result looks like, and what an empty result does and doesn't mean.

Some queries aren't security detections. They're there for troubleshooting log ingestion and for finding field names.

## How to use a query

1. Open the query's `.yaml` file and copy everything under `query:` into the Huntress SIEM search box (ES|QL mode).
2. Set the time picker to the period you want to search. Wide windows work but take longer (see [Read this first](#read-this-first)).
3. Replace every value listed under `placeholders`, for example `<ip>`. Leaving a placeholder in returns nothing, and nothing looks like a clean result.
4. Read the result against `outcomes`: what rows mean, what an empty result means (and when it isn't clean), and what an error usually means.
5. Check `known_limits` before you treat a result as complete.

## Read this first

Huntress SIEM runs a restricted ES|QL. These rules come from testing against live tenants. Where Huntress's own docs say something different, the tested behavior is what's listed here.

| Rule | Detail |
|---|---|
| Source is `from logs` | `FROM logs*` and `FROM logs-*` fail with "Not all query parsed". |
| Wide windows work | Huntress reads the whole picker window, newest first, in 4-hour steps. Wide windows are complete; they just take longer. |
| Never use `limit` | Any `limit` (10 or 200 alike, raw or `stats`) makes the search read only the **last 4 hours of the picker window**. If those last 4 hours are all in the future, the result is empty. The results grid already pages rows. |
| `LIKE` uses `*` | `%` is a literal character, so `LIKE "%admin%"` matches nothing. Huntress's ES\|QL guide shows `%`; it's wrong. |
| `==` is case sensitive | So are field names (`winlog.event_data.Ipaddress` and `IpAddress` are different fields). Use `TO_LOWER(field) == "value"` for exact case-insensitive matches and `CONTAINS(field, "text")` for case-insensitive partial matches. The same operation can appear with different casing, for example `UserLoggedIn` and `UserLoggedin`. |
| `message` is a summary | It holds one line like "User successfully logged in." and never contains IPs, users or IDs. Don't search it for IOCs. Use `CONTAINS(event.original, "text")` to search the raw event. |
| Watch `WHERE` after `STATS` | A `WHERE` after a `STATS` that includes `MIN(@timestamp)` or `MAX(@timestamp)` returns no rows. Filter on counts in a query without the timestamp aggregations. |
| Results stop at 1,000 rows | A `stats` result shows at most 1,000 rows. In a wide window across many tenants, sort so the rows you need come first, or narrow the window. |
| `count_distinct` on huge fields | `count_distinct` was exact up to a few thousand distinct values but returned partial results (half a day of a one-day window) on a field with tens of thousands of values, like a record ID. Use it on users or IPs, not IDs. |
| Aggregation stopped early | Very wide or heavy searches (many `CONTAINS` terms, long `IN` lists over many days of a large source) can end with "Aggregation stopped early" and no usable result. Split the window and run it in parts. |
| One `STATS` per query | Chaining a second `STATS` after the first (`STATS ... BY a, b \| STATS ... BY a`) returned no rows. |
| Wait for Done | A `stats` search shows nothing until it's finished ("Aggregating results..." walks back through the window). A raw search shows the newest 100 rows first and loads older rows only as you scroll; scroll until the grid says Done before treating a short or empty result as complete. |
| Headers aren't field names | The grid relabels some columns (for example `itdr.ClientIP` shows as `source.ip`) and always adds Organization. Take field names from a row's details. |
| Missing fields count as null | `COUNT(field)` counts only rows where the field exists (Huntress's docs say missing fields read as empty values; testing showed otherwise). Empty strings still count. |
| Functions confirmed | `TO_LOWER`, `CONTAINS`, `CIDR_MATCH`, `IN (...)`, `COUNT`, `count_distinct`, `MIN`, `MAX`, `SORT` after `STATS`. `TO_STRING` fails. `EVAL` with `CASE(condition, 1, 0)` works for counting several conditions side by side, but `AND` inside `CASE` fails to parse; keep each `CASE` to one condition. A `WHERE` on the summed columns after `STATS` works (`WHERE failures > 0 AND successes > 0`). Huntress also documents `DROP`, `RENAME` and `MV_EXPAND`; the queries here don't use them. |

**About the time picker:**

- The picker shows your local time. A window ending in the future is fine; it returns what has arrived so far.
- The picker doesn't filter on `@timestamp` alone. A one-day window can hold events whose `@timestamp` falls on the next day (host clocks or time zone settings). To filter on event time, add `@timestamp >= "2026-10-19T00:00:00Z"` style conditions; they compare as text, so exact boundaries can be off by a fraction of a second.

Huntress lists retention as 30 days hot and 1 year cold by default, with a 90 day hot / 7 year cold add-on.

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
| Exchange admin actions | `itdr.Parameters.Name` and `itdr.Parameters.Value` list cmdlet parameters side by side (inbox rules, Set-Mailbox, permissions, transport rules). Both hold every parameter of the call in one value, so search them with `CONTAINS(event.original, "...")`. |
| Directory changes | `itdr.Target.ID`, `itdr.ModifiedProperties.Name`, `.NewValue`, `.OldValue` (role, app, consent and user changes) |
| Raw details | `itdr.ExtendedProperties.Value` holds result detail, user agent and request type as one comma-joined string. Device code sign-ins carry `Cmsi:Cmsi` here. |
| Traps | Some operation names end with a period (for example `Enable Strong Authentication.`, while `UserLoggedIn` has none); match those with `LIKE` or `TO_LOWER(...) LIKE`. Anonymous Microsoft Forms responses log IP `0.0.0.0`. App directory actions show `itdr.UserId` as `ServicePrincipal_<guid>`, the object ID, not the app ID. The certificates and secrets operation names contain an en dash, so match them with `CONTAINS(itdr.Operation, "Certificates and secrets management")`. |

### Cisco Duo

| Item | Detail |
|---|---|
| Provider | `Duo` |
| Authentication records | `duo.email`, `duo.result` (`success`, `denied`, `fraud`), `duo.reason` (for example `user_approved`, `no_response`), `duo.factor` (for example `duo_push`, `verified_duo_push`, `sms_passcode`), `duo.application.name`, `duo.access_device.ip`, `duo.access_device.location.*` |
| Telephony records | `duo.context`, `duo.phone`, `duo.type` (`sms`, `phone`) |
| Traps | All values are lowercase. There's no `allow` result. Bypass code logins are a `success` with reason `bypass_user` and an empty factor. |

### FortiGate

| Item | Detail |
|---|---|
| Provider | `Syslog-Fortigate` (lowercase g; Huntress's FortiGate doc says `Syslog-FortiGate`, which matches nothing) |
| Common fields | `event.code`, `fortigate.duser`, `fortigate.src`, `fortigate.dst`, `fortigate.reason`, `fortigate.outcome`, `fortigate.FTNTFGTmethod`, `fortigate.FTNTFGTprofile`, `fortigate.FTNTFGTtunnelid`, `fortigate.FTNTFGTtunnelip` |
| Traps | `event.name` is only a category label like `event:vpn`. On SSL-VPN events `fortigate.src` is empty and the remote IP is in `source.ip` and `fortigate.dst`. `count_distinct(fortigate.duser)` empties the whole result. Raw message text is in `event.original` (CEF `msg=`). |
| Codes used | 32001/32002 admin login success/failure, 39426 SSL-VPN login failure, 39424/39947/39948 SSL-VPN tunnel up/up/down, 43008/43009/43010 local auth success/failure/lockout, 44546/44547 configuration changed (`fortigate.FTNTFGTcfgpath` is the section, `fortigate.FTNTFGTcfgattr` the values, `fortigate.sproc` how the admin connected). 37130 is an IPsec phase 2 error, not an SSL-VPN failure. |

### SonicWall

| Item | Detail |
|---|---|
| Provider | `Syslog-SonicWall` |
| Common fields | `event.code` (equals the SonicWall message ID `sonicwall.m`), `sonicwall.msg`, `sonicwall.usr`, `sonicwall.sn` (serial), `sonicwall.src`, `sonicwall.dst`, `sonicwall.note`, `source.ip`, `host.ip` |
| Traps | `host.hostname` is never populated; identify the firewall by `sonicwall.sn` or `host.ip`. `sonicwall.sess` doesn't exist under that name. Message ID 200 is CLI administrator login denied. 1382 is configuration succeeded (the setting is in `sonicwall.msg`), and 994/995 mark a config mode admin session starting and ending. SonicWall documents the login and logout codes under the Authentication Access category, so check that category is sent to syslog. |

### Meraki MX

| Item | Detail |
|---|---|
| Provider | `Syslog-Meraki` (MX syslog). The separate Meraki cloud API integration uses `MerakiCloud`. |
| Common fields | `meraki.event_type` (the Meraki syslog category, for example `events`), `meraki.event_description` (for example `content_filtering_block`, `authentication`, `dhcp lease`), `host.hostname`, `host.ip`. Content filtering blocks add `meraki.category0`, `meraki.url`, `meraki.client_ip` and sometimes `user.name`. |
| Traps | `security_event` (IDS and malware scan results) is only sent when the MX syslog server has the Security events role enabled. |

### Palo Alto

| Item | Detail |
|---|---|
| Provider | `Syslog-PaloAlto` |
| Common fields | `event.code` (log type and subtype joined, for example `threat_url`, `threat_spyware`, `threat_file`, `system_general`), `event.action` (`alert`, `block-url`, `drop`, ...), `palo_alto.threat_id`, `palo_alto.threat_category`, `palo_alto.severity`, `palo_alto.category` (URL category), `palo_alto.url_filename` (the URL), `palo_alto.rule_name`, `palo_alto.device_name`, `palo_alto.direction`, `source.ip`, `destination.ip` |
| Traps | Traffic logs only arrive if the log forwarding profile sends them. DNS-based spyware signatures put the domain inside `palo_alto.threat_id` (`generic:<domain>(<id>)`). |

### WatchGuard

| Item | Detail |
|---|---|
| Provider | `Syslog-XTM` |
| Common fields | `event.code` (8-character hex message ID, text), `event.action` (`Allow`, `Deny`, `logon`, `logon-failed`, `connect`, `disconnect`), `user.name`, `source.ip`, `source.as.organization.name`, `xtm.auth_server`, `xtm.user_type`, `event.reason` |
| Traps | Message IDs are text, so quote them (`event.code=="11000005"`). On some logon messages `xtm.user_type` holds the unparsed end of the message, including the Firebox serial. |

### Google Workspace

| Item | Detail |
|---|---|
| Provider | `ITDR-GWS` |
| Common fields | `event.code` (Google activity type, for example `login`, `password_change`, `recovery_info_change`, `account_warning`), `event.action` (event name, for example `login_success`, `login_failure`, `password_edit`), `event.outcome`, `user.email`, `source.ip`, `source.as.organization.name`, `google.events.parameters.name` and `.value` |
| Traps | Drive, Gmail and Admin console activity may not be ingested; check which `event.code` values arrive. |

### Huntress Platform

| Item | Detail |
|---|---|
| Provider | `Huntress Platform` (the Huntress portal's own audit log) |
| Common fields | `event.action` (for example `agent-uninstall`, `account-accessed`, `remediations-approved`, `account-invitation-create`), `event.outcome`, `client.user.email`, `client.user.role`, `client.ip`, `client.as.organization.name`, `account.name`, `event.details.agent_hostnames`, `user_agent.original` |
| Traps | These are actions taken in the Huntress console, not on endpoints. |

### Ubiquiti UniFi

| Item | Detail |
|---|---|
| Provider | `Syslog-Ubiquiti` |
| Common fields | `event.code` (UniFi event ID as text, or `traffic` for flow logs), `event.name` (for example `Blocked by Firewall`, `Admin Accessed UniFi OS`, `Network Accessed`), `host.hostname`, `unifi_network.UNIFIcategory`, `unifi_network.UNIFIpolicyName`, `unifi_network.UNIFIrisk`, `unifi_network.UNIFIsrcClientIp`, `unifi_network.UNIFIadmin`, `unifi_os.UNIFIadmin`, `source.ip` |
| Traps | Fields are split by UniFi application (`unifi_network.*`, `unifi_os.*`, `unifi_protect.*`). Event codes are text, so quote them (`event.code=="203"`). |

### SentinelOne

| Item | Detail |
|---|---|
| Provider | `Syslog-SentinelOne` |
| Common fields | `event.code`, `message`, `sentinelone.*` (for example `sentinelone.eventDesc`, `sentinelone.activityType`, `sentinelone.deviceHostName`), `file.hash.sha256`, `file.path`, `process.command_line` |
| Traps | `host.hostname` is blank; the endpoint name is in `sentinelone.deviceHostName`. Only alerts and threat activity are ingested, not endpoint telemetry. Common codes: 19 new active threat, 2001 kill, 2004 quarantine, 2009 quarantine failed, 2028 incident status changed, 2030 analyst verdict changed. |

### Windows event logs

| Item | Detail |
|---|---|
| Providers | `Microsoft-Windows-Security-Auditing`, `Microsoft-Windows-DNS-Client`, `Microsoft-Windows-HttpService`, `Service Control Manager` (System log, service installs 7045), `Microsoft-Windows-Eventlog` (log cleared 104 and 1102), `Microsoft-Windows-PowerShell` (script blocks 4104), `Quick Assist`, `ScreenConnect` (client events 100 connect, 101 disconnect, 201 file transfer) |
| Common fields | `event.code` (numeric; quoted and unquoted both work), `host.hostname`, `user.name`, `winlog.event_data.*` (string values) |
| More fields | 7045: `winlog.event_data.ServiceName`, `.ImagePath`, `.AccountName`, `.StartType`. 4104: `winlog.event_data.ScriptBlockText`, `.Path`. ScreenConnect: `winlog.event_data.RelayServer`, `.InstanceFingerprint`, `event.action`. Logon type (`winlog.event_data.LogonType`) is a string: match `"10"`, not `10`. Process creation (4688) isn't collected in most environments, so command lines come from PowerShell 4104 instead. |
| Traps | Field names are case sensitive (`winlog.event_data.Ipaddress` on DNS-Client). Quick Assist events carry only the host and time (blank message, no event data). Many events only exist when the matching audit policy is on; each query's `outcomes.empty` names the setting. |

## Find a query

### By data source

**All sources**

| Query | Use it to |
|---|---|
| [ingestion-health-by-provider.yaml](All%20Sources/ingestion-health-by-provider.yaml) | See every log source's event count and last event, stalest first |

**ITDR**

| Query | Use it to |
|---|---|
| [app-activity-by-app-id.yaml](ITDR/app-activity-by-app-id.yaml) | See what one app identity did, by app ID |
| [conditional-access-policy-changes.yaml](ITDR/conditional-access-policy-changes.yaml) | List Conditional Access and other Entra policy changes |
| [connectwise-cloud-backup-app-id-sweep.yaml](ITDR/connectwise-cloud-backup-app-id-sweep.yaml) | Sweep for the ConnectWise Cloud Backup (SkyKick) app IDs |
| [connectwise-cloud-backup-ioc-ip-detail.yaml](ITDR/connectwise-cloud-backup-ioc-ip-detail.yaml) | List raw records from the ConnectWise Cloud Backup campaign IPs |
| [connectwise-cloud-backup-ioc-ip-sweep.yaml](ITDR/connectwise-cloud-backup-ioc-ip-sweep.yaml) | Summarize activity from the ConnectWise Cloud Backup campaign IPs |
| [connectwise-skykick-app-name-search.yaml](ITDR/connectwise-skykick-app-name-search.yaml) | Find ConnectWise or SkyKick apps by display name |
| [entra-account-lockouts.yaml](ITDR/entra-account-lockouts.yaml) | Rank accounts and IPs by smart lockouts |
| [entra-app-credentials-and-owners-added.yaml](ITDR/entra-app-credentials-and-owners-added.yaml) | Find secrets, certificates and owners added to apps |
| [entra-find-all-events-in-a-session.yaml](ITDR/entra-find-all-events-in-a-session.yaml) | See every record in one browser session, across accounts |
| [entra-mfa-disabled.yaml](ITDR/entra-mfa-disabled.yaml) | Find per-user MFA being turned off |
| [entra-mfa-enabled.yaml](ITDR/entra-mfa-enabled.yaml) | Find per-user MFA being turned on |
| [entra-oauth-consent-and-permission-grants.yaml](ITDR/entra-oauth-consent-and-permission-grants.yaml) | List app consent and permission grants |
| [entra-password-spray-by-ip.yaml](ITDR/entra-password-spray-by-ip.yaml) | Rank IPs by how many accounts they failed against |
| [entra-persistence-operation-inventory.yaml](ITDR/entra-persistence-operation-inventory.yaml) | Count role, app and consent changes by actor |
| [entra-role-member-added.yaml](ITDR/entra-role-member-added.yaml) | Find accounts added to a directory role |
| [entra-user-account-changes.yaml](ITDR/entra-user-account-changes.yaml) | List accounts created, deleted, disabled or reset |
| [entra-user-activity-by-actor-ip-address.yaml](ITDR/entra-user-activity-by-actor-ip-address.yaml) | Summarize everything one IP did |
| [entra-user-login-blocked-by-conditional-access.yaml](ITDR/entra-user-login-blocked-by-conditional-access.yaml) | List sign-ins Conditional Access blocked |
| [entra-user-login-failures.yaml](ITDR/entra-user-login-failures.yaml) | List failed sign-ins |
| [entra-user-login-invalid-username-or-password.yaml](ITDR/entra-user-login-invalid-username-or-password.yaml) | List wrong-password failures |
| [entra-user-login-strong-auth-enrollment-required.yaml](ITDR/entra-user-login-strong-auth-enrollment-required.yaml) | List sign-ins interrupted for MFA |
| [impossible-travel-signin.yaml](ITDR/impossible-travel-signin.yaml) | Rank accounts by distinct sign-in IPs in a day |
| [inbox-rule-created-or-changed.yaml](ITDR/inbox-rule-created-or-changed.yaml) | List every inbox rule created or changed |
| [inbox-rule-hiding-or-forwarding.yaml](ITDR/inbox-rule-hiding-or-forwarding.yaml) | Find rules that forward, delete or hide mail |
| [itdr-coverage-check.yaml](ITDR/itdr-coverage-check.yaml) | Confirm ITDR data covers a window before trusting a negative |
| [mailbox-delegation-added.yaml](ITDR/mailbox-delegation-added.yaml) | Find full access, send as and send on behalf grants |
| [mailbox-forwarding-set.yaml](ITDR/mailbox-forwarding-set.yaml) | Find mailbox-level forwarding changes |
| [oauth-device-code-flow-authentication.yaml](ITDR/oauth-device-code-flow-authentication.yaml) | Find device code sign-ins |
| [sharepoint-anonymous-link-created.yaml](ITDR/sharepoint-anonymous-link-created.yaml) | List anyone-with-the-link sharing |
| [sign-in-success-after-failures.yaml](ITDR/sign-in-success-after-failures.yaml) | Find IP and account pairs with both failed and successful sign-ins |
| [transport-rule-changes.yaml](ITDR/transport-rule-changes.yaml) | List Exchange mail flow rule changes |
| [user-activity-summary.yaml](ITDR/user-activity-summary.yaml) | Summarize everything one account did, by workload, operation and IP |
| [user-signin-source-ips.yaml](ITDR/user-signin-source-ips.yaml) | List one user's sign-in IPs |

**Cisco Duo**

| Query | Use it to |
|---|---|
| [all-logs-by-event-provider.yaml](Cisco%20Duo/all-logs-by-event-provider.yaml) | Check Duo logs are arriving and see the fields |
| [authorization-failure.yaml](Cisco%20Duo/authorization-failure.yaml) | List denied authentications |
| [authorization-success.yaml](Cisco%20Duo/authorization-success.yaml) | List successful authentications |
| [bypass-code-authentication.yaml](Cisco%20Duo/bypass-code-authentication.yaml) | List logins that used a bypass code instead of MFA |
| [duo-authentication-failure-spike.yaml](Cisco%20Duo/duo-authentication-failure-spike.yaml) | Find users with five or more failures |
| [duo-type-sms.yaml](Cisco%20Duo/duo-type-sms.yaml) | Find SMS passcodes sent |
| [mfa-push-fatigue-deny-then-allow.yaml](Cisco%20Duo/mfa-push-fatigue-deny-then-allow.yaml) | Spot denied pushes followed by an approval |

**FortiGate**

| Query | Use it to |
|---|---|
| [admin-login-from-external-ip.yaml](Fortigate/admin-login-from-external-ip.yaml) | Find successful admin logins from public IPs |
| [admin-logins-on-any-interface.yaml](Fortigate/admin-logins-on-any-interface.yaml) | List admin login successes and failures |
| [all-logs-by-hostname.yaml](Fortigate/all-logs-by-hostname.yaml) | Check FortiGate logs are arriving and see the fields |
| [config-changes.yaml](Fortigate/config-changes.yaml) | Summarize configuration changes by admin and config path |
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
| [cli-admin-login-denied.yaml](Sonicwall/cli-admin-login-denied.yaml) | Rank sources of failed CLI admin logins (ID 200) |
| [config-changes.yaml](Sonicwall/config-changes.yaml) | List configuration changes and config mode admin sessions |
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
| [Meraki: content-filtering-blocks.yaml](Meraki/content-filtering-blocks.yaml) | Summarize content filtering blocks by category and client |
| [SentinelOne: all-logs-by-event-provider.yaml](SentinelOne/all-logs-by-event-provider.yaml) | List SentinelOne alerts and threat activity |
| [SentinelOne: threat-mitigation-by-host.yaml](SentinelOne/threat-mitigation-by-host.yaml) | Count new threats, kills, quarantines and failed quarantines per host |

**Palo Alto**

| Query | Use it to |
|---|---|
| [all-logs-by-hostname.yaml](Palo%20Alto/all-logs-by-hostname.yaml) | Check Palo Alto logs are arriving, by firewall and log type |
| [threat-detections.yaml](Palo%20Alto/threat-detections.yaml) | Summarize medium and higher threat detections |
| [url-filtering-blocks.yaml](Palo%20Alto/url-filtering-blocks.yaml) | Summarize URL filtering blocks by category |

**WatchGuard**

| Query | Use it to |
|---|---|
| [all-logs-by-hostname.yaml](WatchGuard/all-logs-by-hostname.yaml) | Check WatchGuard logs are arriving, by Firebox and message ID |
| [failed-logons.yaml](WatchGuard/failed-logons.yaml) | Rank VPN and management logon failures |
| [successful-logons.yaml](WatchGuard/successful-logons.yaml) | Summarize management and VPN logons by user and source |

**Google Workspace**

| Query | Use it to |
|---|---|
| [account-security-changes.yaml](Google%20Workspace/account-security-changes.yaml) | List password, recovery and passkey changes and Google's account warnings |
| [all-logs-by-event-provider.yaml](Google%20Workspace/all-logs-by-event-provider.yaml) | Check Google Workspace logs are arriving and see the event types |
| [login-failures.yaml](Google%20Workspace/login-failures.yaml) | Rank login failures by user, IP and network owner |

**Huntress Platform**

| Query | Use it to |
|---|---|
| [agent-uninstalled.yaml](Huntress%20Platform/agent-uninstalled.yaml) | List agents uninstalled from the Huntress portal, and by whom |
| [all-activity-by-action.yaml](Huntress%20Platform/all-activity-by-action.yaml) | Count Huntress portal actions by user |

**Ubiquiti**

| Query | Use it to |
|---|---|
| [admin-access.yaml](Ubiquiti/admin-access.yaml) | List admin sign-ins to UniFi consoles and the Network app |
| [all-logs-by-hostname.yaml](Ubiquiti/all-logs-by-hostname.yaml) | Check UniFi logs are arriving and see the event types |
| [firewall-blocks.yaml](Ubiquiti/firewall-blocks.yaml) | Summarize gateway firewall blocks by policy and client |

**Windows event logs**

| Query | Use it to |
|---|---|
| [account-lockouts.yaml](Windows%20Event/account-lockouts.yaml) | Rank AD account lockouts (4740) by account and caller |
| [account-logon-failed.yaml](Windows%20Event/account-logon-failed.yaml) | List failed logons (4625) |
| [account-management-events.yaml](Windows%20Event/account-management-events.yaml) | List accounts created, enabled, disabled, deleted |
| [admin-password-reset.yaml](Windows%20Event/admin-password-reset.yaml) | List passwords reset by another account (4724) |
| [dns-client-event-provider.yaml](Windows%20Event/dns-client-event-provider.yaml) | Troubleshoot DNS client problems |
| [event-log-cleared.yaml](Windows%20Event/event-log-cleared.yaml) | Find event logs being cleared (104, 1102) |
| [event-provider-by-hostname.yaml](Windows%20Event/event-provider-by-hostname.yaml) | See all Security events from one host |
| [events-from-a-specific-process.yaml](Windows%20Event/events-from-a-specific-process.yaml) | See Security events naming one process |
| [gpo-changes.yaml](Windows%20Event/gpo-changes.yaml) | List directory and Group Policy object changes |
| [httpservice-event-provider.yaml](Windows%20Event/httpservice-event-provider.yaml) | List HTTP.sys configuration changes |
| [kerberoasting-rc4-service-ticket-request.yaml](Windows%20Event/kerberoasting-rc4-service-ticket-request.yaml) | Find RC4 service tickets (Kerberoasting) |
| [kerberos-preauth-failures.yaml](Windows%20Event/kerberos-preauth-failures.yaml) | Rank IPs by accounts failing Kerberos pre-auth (4771) |
| [key-storage-provider.yaml](Windows%20Event/key-storage-provider.yaml) | List key storage operations |
| [local-user-account-created.yaml](Windows%20Event/local-user-account-created.yaml) | List new user accounts (4720) |
| [overpass-the-hash-rc4-tgt-request.yaml](Windows%20Event/overpass-the-hash-rc4-tgt-request.yaml) | Find RC4 TGT requests (overpass-the-hash) |
| [pass-the-hash-ntlm-network-logon-zero-key.yaml](Windows%20Event/pass-the-hash-ntlm-network-logon-zero-key.yaml) | Find NTLM network logons with key length 0 |
| [powershell-suspicious-script-block.yaml](Windows%20Event/powershell-suspicious-script-block.yaml) | Find download cradles and Defender tampering in PowerShell (4104) |
| [privileged-group-membership-change.yaml](Windows%20Event/privileged-group-membership-change.yaml) | List members added to security groups |
| [quick-assist-activity-by-host.yaml](Windows%20Event/quick-assist-activity-by-host.yaml) | List hosts where Quick Assist ran |
| [rdp-logons.yaml](Windows%20Event/rdp-logons.yaml) | Summarize RDP logons (4624 type 10) |
| [registry-key-modification.yaml](Windows%20Event/registry-key-modification.yaml) | Find Run and RunOnce key changes |
| [scheduled-task-creation.yaml](Windows%20Event/scheduled-task-creation.yaml) | List new scheduled tasks |
| [screenconnect-relay-servers.yaml](Windows%20Event/screenconnect-relay-servers.yaml) | List ScreenConnect relay servers, rarest first |
| [service-installed.yaml](Windows%20Event/service-installed.yaml) | List new services (7045), rarest first |
| [sonicwall-vpn-ioc-driver-installed-by-attacker.yaml](Windows%20Event/sonicwall-vpn-ioc-driver-installed-by-attacker.yaml) | Sweep for published attacker drivers |
| [sonicwall-vpn-ioc-ransomware-executables.yaml](Windows%20Event/sonicwall-vpn-ioc-ransomware-executables.yaml) | Sweep for published attacker tools |
| [sonicwall-vpn-ioc-user-created-by-attacker.yaml](Windows%20Event/sonicwall-vpn-ioc-user-created-by-attacker.yaml) | Sweep for published attacker account names |
| [username-is-administrator.yaml](Windows%20Event/username-is-administrator.yaml) | See events for administrator accounts |

### By scenario

| You're looking at | Start with |
|---|---|
| A suspicious Microsoft 365 sign-in | [entra-user-activity-by-actor-ip-address.yaml](ITDR/entra-user-activity-by-actor-ip-address.yaml), then [entra-find-all-events-in-a-session.yaml](ITDR/entra-find-all-events-in-a-session.yaml) |
| A possible account takeover | [user-activity-summary.yaml](ITDR/user-activity-summary.yaml), [sign-in-success-after-failures.yaml](ITDR/sign-in-success-after-failures.yaml), [impossible-travel-signin.yaml](ITDR/impossible-travel-signin.yaml), [entra-mfa-disabled.yaml](ITDR/entra-mfa-disabled.yaml), [entra-user-login-failures.yaml](ITDR/entra-user-login-failures.yaml), then the business email compromise row |
| Business email compromise (suspicious inbox rule, forwarding) | [inbox-rule-hiding-or-forwarding.yaml](ITDR/inbox-rule-hiding-or-forwarding.yaml), [inbox-rule-created-or-changed.yaml](ITDR/inbox-rule-created-or-changed.yaml), [mailbox-forwarding-set.yaml](ITDR/mailbox-forwarding-set.yaml), [mailbox-delegation-added.yaml](ITDR/mailbox-delegation-added.yaml), [transport-rule-changes.yaml](ITDR/transport-rule-changes.yaml) |
| Entra persistence or privilege escalation | [entra-persistence-operation-inventory.yaml](ITDR/entra-persistence-operation-inventory.yaml), then [entra-role-member-added.yaml](ITDR/entra-role-member-added.yaml), [entra-oauth-consent-and-permission-grants.yaml](ITDR/entra-oauth-consent-and-permission-grants.yaml), [entra-app-credentials-and-owners-added.yaml](ITDR/entra-app-credentials-and-owners-added.yaml), [entra-user-account-changes.yaml](ITDR/entra-user-account-changes.yaml), [conditional-access-policy-changes.yaml](ITDR/conditional-access-policy-changes.yaml) |
| Illicit OAuth consent | [entra-oauth-consent-and-permission-grants.yaml](ITDR/entra-oauth-consent-and-permission-grants.yaml), [entra-app-credentials-and-owners-added.yaml](ITDR/entra-app-credentials-and-owners-added.yaml) |
| Data shared out of SharePoint or OneDrive | [sharepoint-anonymous-link-created.yaml](ITDR/sharepoint-anonymous-link-created.yaml) |
| Device code phishing | [oauth-device-code-flow-authentication.yaml](ITDR/oauth-device-code-flow-authentication.yaml) |
| MFA fatigue | [mfa-push-fatigue-deny-then-allow.yaml](Cisco%20Duo/mfa-push-fatigue-deny-then-allow.yaml), [duo-authentication-failure-spike.yaml](Cisco%20Duo/duo-authentication-failure-spike.yaml) |
| Password spraying or brute force | [entra-password-spray-by-ip.yaml](ITDR/entra-password-spray-by-ip.yaml), [sign-in-success-after-failures.yaml](ITDR/sign-in-success-after-failures.yaml), [entra-account-lockouts.yaml](ITDR/entra-account-lockouts.yaml), [entra-user-login-invalid-username-or-password.yaml](ITDR/entra-user-login-invalid-username-or-password.yaml), [ssl-vpn-auth-failure-spike.yaml](Fortigate/ssl-vpn-auth-failure-spike.yaml), [account-logon-failed.yaml](Windows%20Event/account-logon-failed.yaml) |
| An exposed firewall admin interface | [admin-logins-on-any-interface.yaml](Fortigate/admin-logins-on-any-interface.yaml), [admin-login-from-external-ip.yaml](Fortigate/admin-login-from-external-ip.yaml), [admin-wan-login.yaml](Sonicwall/admin-wan-login.yaml), [cli-admin-login-denied.yaml](Sonicwall/cli-admin-login-denied.yaml), [successful-logons.yaml](WatchGuard/successful-logons.yaml), then [Fortigate/config-changes.yaml](Fortigate/config-changes.yaml) and [Sonicwall/config-changes.yaml](Sonicwall/config-changes.yaml) for what the admin changed |
| VPN brute force or credential stuffing | [ssl-vpn-auth-failure-spike.yaml](Fortigate/ssl-vpn-auth-failure-spike.yaml), [failed-logons.yaml](WatchGuard/failed-logons.yaml), [successful-logons.yaml](WatchGuard/successful-logons.yaml) |
| A device reaching malicious sites | [threat-detections.yaml](Palo%20Alto/threat-detections.yaml), [url-filtering-blocks.yaml](Palo%20Alto/url-filtering-blocks.yaml), [content-filtering-blocks.yaml](Meraki/content-filtering-blocks.yaml) |
| A firewall firmware change | [firmware-version-change.yaml](Fortigate/firmware-version-change.yaml) |
| A new account or privilege change | [account-management-events.yaml](Windows%20Event/account-management-events.yaml), [privileged-group-membership-change.yaml](Windows%20Event/privileged-group-membership-change.yaml), [admin-password-reset.yaml](Windows%20Event/admin-password-reset.yaml) |
| Persistence on a Windows host | [scheduled-task-creation.yaml](Windows%20Event/scheduled-task-creation.yaml), [registry-key-modification.yaml](Windows%20Event/registry-key-modification.yaml), [service-installed.yaml](Windows%20Event/service-installed.yaml) |
| RDP brute force or lateral movement | [rdp-logons.yaml](Windows%20Event/rdp-logons.yaml), [account-logon-failed.yaml](Windows%20Event/account-logon-failed.yaml), [kerberos-preauth-failures.yaml](Windows%20Event/kerberos-preauth-failures.yaml), [account-lockouts.yaml](Windows%20Event/account-lockouts.yaml) |
| Remote access tool abuse or help desk scam | [screenconnect-relay-servers.yaml](Windows%20Event/screenconnect-relay-servers.yaml), [quick-assist-activity-by-host.yaml](Windows%20Event/quick-assist-activity-by-host.yaml), [service-installed.yaml](Windows%20Event/service-installed.yaml) |
| Ransomware precursors (new services, PowerShell, cleared logs) | [service-installed.yaml](Windows%20Event/service-installed.yaml), [powershell-suspicious-script-block.yaml](Windows%20Event/powershell-suspicious-script-block.yaml), [event-log-cleared.yaml](Windows%20Event/event-log-cleared.yaml) |
| MFA bypassed | [bypass-code-authentication.yaml](Cisco%20Duo/bypass-code-authentication.yaml), [entra-mfa-disabled.yaml](ITDR/entra-mfa-disabled.yaml) |
| An endpoint threat that wasn't cleaned up | [threat-mitigation-by-host.yaml](SentinelOne/threat-mitigation-by-host.yaml) |
| A Google Workspace account takeover | [login-failures.yaml](Google%20Workspace/login-failures.yaml), [account-security-changes.yaml](Google%20Workspace/account-security-changes.yaml) |
| Misuse of the Huntress portal | [agent-uninstalled.yaml](Huntress%20Platform/agent-uninstalled.yaml), [all-activity-by-action.yaml](Huntress%20Platform/all-activity-by-action.yaml) |
| Unexpected access to network gear | [admin-access.yaml](Ubiquiti/admin-access.yaml), [firewall-blocks.yaml](Ubiquiti/firewall-blocks.yaml) |
| Kerberos or NTLM credential abuse | [kerberoasting-rc4-service-ticket-request.yaml](Windows%20Event/kerberoasting-rc4-service-ticket-request.yaml), [overpass-the-hash-rc4-tgt-request.yaml](Windows%20Event/overpass-the-hash-rc4-tgt-request.yaml), [pass-the-hash-ntlm-network-logon-zero-key.yaml](Windows%20Event/pass-the-hash-ntlm-network-logon-zero-key.yaml) |
| An IOC sweep | [entra-user-activity-by-actor-ip-address.yaml](ITDR/entra-user-activity-by-actor-ip-address.yaml), [sonicwall-vpn-ioc-login-by-ip.yaml](Sonicwall/sonicwall-vpn-ioc-login-by-ip.yaml) |
| The ConnectWise Cloud Backup (SkyKick) compromise, October 2026 | [connectwise-cloud-backup-ioc-ip-sweep.yaml](ITDR/connectwise-cloud-backup-ioc-ip-sweep.yaml), [connectwise-cloud-backup-ioc-ip-detail.yaml](ITDR/connectwise-cloud-backup-ioc-ip-detail.yaml), [connectwise-cloud-backup-app-id-sweep.yaml](ITDR/connectwise-cloud-backup-app-id-sweep.yaml), [connectwise-skykick-app-name-search.yaml](ITDR/connectwise-skykick-app-name-search.yaml), then [entra-persistence-operation-inventory.yaml](ITDR/entra-persistence-operation-inventory.yaml) |
| Proving a negative hunt result | [itdr-coverage-check.yaml](ITDR/itdr-coverage-check.yaml) over the same window |
| Whether logs are arriving | [ingestion-health-by-provider.yaml](All%20Sources/ingestion-health-by-provider.yaml), then the "all logs" query for the source |

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
- Log source: one tag naming the data source, for example `windows.event`, `cisco.duo`, `fortigate`, `microsoft.entra.id`, `sonicwall`, `meraki`, `sentinelone`, `palo.alto`, `watchguard`, `google.workspace`, `huntress.platform`, `ubiquiti`, and `huntress.siem` for queries that cover every source

Utility and starter queries that don't map to a technique carry only the log source tag.

Queries that sweep for published IOCs (attacker IPs, app IDs) also carry `ioc`. The lint check skips its public IP and GUID checks only for files with that tag.

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
