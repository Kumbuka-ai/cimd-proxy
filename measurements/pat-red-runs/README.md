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
