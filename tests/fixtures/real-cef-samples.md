# Real captured CEF samples

Raw CEF lines captured from a live UDM Pro (Network app 10.6.101), pasted
here as ground truth for parser fixtures. Paste new samples at the end with
a short header noting the date, what triggered the event, and the log
category shown in the UniFi Network UI. Copy the *exact* text shown when
expanding a log entry, or the raw line from a syslog capture — don't
paraphrase or reformat it.

Each sample here should eventually get promoted into a test fixture in
`tests/parser/*.test.ts` once it's been used to validate or correct the
parser. Note in this file whether that's been done yet.

---

## 2026-08-29 — Security / Intrusion Prevention (IDS/IPS block)

Trigger: a real inbound connection attempt from an IP on the DShield Block
List, blocked automatically by Threat Management. Found via the Network
app's Logs UI (Category = Security), for an event that occurred
2026-08-28 21:29 local time — predates this project's syslog capture
listener being enabled, so it was copied from the UI rather than captured
live over the wire.

Status: used to fix `src/parser/normalize.ts`'s category mapping (which
assumed a `UNIFIsubCategory` key that doesn't exist for this event type),
signature extraction (real rule name is in `UNIFIipsSignature`, not the
standard CEF `cs1` key), and event-time extraction (real timestamp is in
`UNIFIutcTime`, not the standard CEF `rt` key). See test fixture
`IPS_BLOCK_CEF` in `tests/parser/normalize.test.ts`.

```
CEF:0|Ubiquiti|UniFi Network|10.6.101|201|Threat Detected and Blocked|7|UNIFIcategory=Security UNIFIhost=UDM-Pro proto=TCP spt=53250 dpt=32400 act=blocked app=Other UNIFIrisk=medium UNIFIpolicyName=DShield Block List UNIFIpolicyType=IDS/IPS UNIFIdirection=incoming deviceOutboundInterface=Default UNIFIdeviceMac=68:d7:9a:35:af:41 UNIFIdeviceName=UDM-Pro UNIFIdeviceModel=UDM-Pro UNIFIdeviceIp=192.168.1.1 UNIFIdeviceVersion=5.1.31 src=198.235.24.95 dst=192.168.1.26 UNIFIsrcRegion=US UNIFIdstZone=Internal UNIFItotalBytes=58 UNIFItotalPackets=1 UNIFIpacketsReceived=0 UNIFIpacketsSent=1 UNIFIbytesReceived=0 UNIFIbytesSent=58 UNIFIflowCount=1 UNIFIflowId=null UNIFIflowStartTime=Aug 28, 2026 at 9:29:29.569 PM UNIFIipsSessionId=825220889423931 UNIFIipsSignature=ET DROP Dshield Block Listed Source group 1 UNIFIipsSignatureId=2402000 UNIFIutcTime=2026-08-29T01:29:30.869Z msg=A network intrusion attempt from 198.235.24.95 to 192.168.1.26 has been detected and blocked.
```

## 2026-08-29 — System / Admin Made Config Changes (UniFi OS level)

Trigger: enabling the Syslog Settings export itself (unifiOS/protect
category toggles), captured live via the syslog listener at 09:28 local
time. Note this comes from a *different* CEF-emitting subsystem than the
Network-app Security event above: Vendor/Product/DeviceVersion here are
`Ubiquiti|UniFi OS|5.1.31` rather than `Ubiquiti|UniFi Network|10.6.101` —
UniFi OS-level events (admin/system settings changes) and UniFi
Network-app-level events (Security, Monitoring, etc.) are emitted with
different Product/DeviceVersion header fields, and OS-level events don't
carry `UNIFIcategory`/`UNIFIsubCategory` at all — they identify the action
via the CEF `Name` field and numeric signature ID instead (`1005` here).

Status: not yet used to change the parser. Currently falls through to
`category: 'unknown'` in `normalize.ts`, which is safe (raw is preserved)
but not ideal — revisit if UniFi OS-level events turn out to matter for
this project's use case (they're admin/system housekeeping, not security
threats, so may not be worth dedicated categorization).

```
CEF:0|Ubiquiti|UniFi OS|5.1.31|1005|Admin Made Config Changes|2|UNIFIhost=Host UNIFIdeviceName=UDM-Pro UNIFIdeviceModel=UDMPRO UNIFIdeviceIp=71.235.83.203 UNIFIdeviceMac=68:D7:9A:35:AF:41 UNIFIdeviceVersion=5.1.31 msg=Ian C. changed Syslog Settings Mode setting from "off" to "external". Source IP: 71.235.83.203
```
