# ADR 0003 — Neutron v2.0 API over direct MySQL

**Status:** accepted

## Context

The metadata layer needs networks, subnets, ports, routers, and routes from Neutron. Direct DB queries are fast (no HTTP overhead), can do JOINs that would otherwise require many API calls, and expose internal Neutron tables.

## Decision

Fetch everything through the versioned Neutron v2.0 REST API; never touch the database.

1. **Schema migrates with every OpenStack release.** Table names, column names, and relationships change. A query that works on one release silently breaks on the next — no warning, no error at startup, just wrong data in the trie.
2. **Security.** The agent would need MySQL credentials with read access to Neutron's full database. That's a much bigger blast radius than read-only API access scoped by a Keystone token.
3. **Bypasses Neutron's business logic.** Some fields are computed on read; querying the DB directly gives raw state without that computation — a source of subtle correctness bugs.
4. **API performance is fine for our use case.** Cold-start makes a handful of paginated API calls (with `fields=...` to trim payloads). All joins happen in Go memory after caching. <1 second total startup overhead.

The same reasoning governs the OVN chassis-MAC question: OVN exposes everything needed via the standard port API (broadened `device_owner` filter), so no OVN Southbound / OVS DB queries either — DB-direct access would reintroduce exactly the schema-migration and blast-radius problems above.

## Consequences

- The agent needs only Keystone credentials and survives OpenStack upgrades that keep the API contract.
- Data the API genuinely doesn't expose is out of reach — acceptable: MACs, CIDRs, ownership, and routes are all in the API.

**When direct DB is the right answer:** when you need data the API doesn't expose (internal IPAM allocation state, raw subnet pool tracking). Not our case.
