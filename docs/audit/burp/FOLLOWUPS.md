# Burp-first follow-ups (collected during worker audits)

## Done
- w014: in-page curl one-liner sweep COMPLETE. All user-facing curl-isms in
  rendered challenge pages were reworded Burp-first (payloadBlock titles now
  read "Burp Repeater" with raw HTTP, "Try it with curl" became "Try it in
  Burp Repeater", race-condition `seq | xargs curl` patterns became Burp
  Intruder nudges). Files touched: bizlogic (3), cors (6), hostheader,
  http/cache-deception, lfi/log-poison, misconfig/put.js, oauth (5),
  postmsg/csrf-action, proto/proto-json, race (6), xxe/xxe-billion-laughs.
- w028: `toolsPill(vuln.tools)` -> `toolsPill(vuln)` fixed in
  modules/ssrf/challenges/basic.js and modules/ssrf/challenges/bypass.js.
  The Tools pill was rendering empty on those two pages because toolsPill
  expects the vuln object, not the tools string.
- w106: audit worker's session was lost before writing its verdict doc.
  Coordinator reviewed the (complete, metadata-only) edits to
  modules/proto/challenges/proto-query.js and
  modules/proto/challenges/proto-unicode-bypass.js, live-verified both
  exploit chains, and wrote docs/audit/burp/w106.md.

## Open (future hardening, not required for the Burp-first doctrine)
- w103: proto-client claim endpoint awards the flag to any non-default theme
  value; a direct Repeater GET also scores. Future hardening could bind the
  claim to an actual browser render.
