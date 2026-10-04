# Observed red runs: personal access tokens

`red_runs.py` removes one guard at a time from the source, runs the test that
guards it and restores the source. Every gate below was seen going red, and
with the assertion that names the gate — not with an unrelated failure.

- `results-unit.txt` — the proxy-side gates (red probes RP8, no Docker needed)
- `results-integration.txt` — the gates measured against PostgreSQL and
  Keycloak 26.7.4 (`--integration`, needs Docker). One line quoted a token
  value from the throwaway test run; it is redacted.

Two kinds of gate are not mutated here, because the proxy holds no line whose
removal would open them: a disabled owner and a foreign signing key are refused
by Keycloak. Their red state is the control run in the same test (an enabled
owner, the published key) and the measurement in
`../jwt-authorization-grant/results.txt` (probes 5a and 5b).

The realm-row mutation shows a second line of defence: without the realm check,
the resource check still refuses (`invalid_target`), and the probe goes red
because it asserts the precise refusal.

## Migrations image and organization binding

The schema is applied by the `cimd-proxy-migrations` image, and the
integration tests build that image from the working tree at the start of every
run. A mutation of a migration or of the image's entrypoint is therefore
measured as it would ship: `img-*` and `db-*` change the SQL file or
`docker/migrations-entrypoint.sh`, the next test session rebuilds the image,
and the probe runs Flyway against PostgreSQL.

- `img-off` — without the "no credentials, nothing to do" branch the image
  reaches the half-configured refusal and exits 2.
- `img-rerun` — an entrypoint that cleans before migrating re-applies the
  migration; the probe sees it in the Flyway history (`installed_on`) and in the
  missing "No migration necessary".
- `org-create`, `kc-org` — restore the old fallback to an empty tenant. The
  unit probe goes red on the status; against PostgreSQL the request fails with
  a 500 instead of the typed refusal, because the table's `CHECK (tenant <> '')`
  refuses the row: the second line of defence, observed.
