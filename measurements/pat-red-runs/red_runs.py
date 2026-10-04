# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Observed red runs for the personal-access-token gates.

Each entry removes one guard from the source, runs the test that guards it,
prints whether it went red and with which assertion, and restores the source in
a ``finally``. A gate that has never been seen failing is not a gate.

Run from the repository root on a clean, committed tree:

    python measurements/pat-red-runs/red_runs.py            # proxy-side gates
    python measurements/pat-red-runs/red_runs.py --integration   # needs Docker
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

PAT = Path("src/cimd_proxy/pat.py")
STORE = Path("src/cimd_proxy/pat_store.py")
MIGRATION = Path("src/cimd_proxy/migrations/V1__personal_access_token.sql")
ENTRYPOINT = Path("docker/migrations-entrypoint.sh")
RP8 = "tests/red_probes/test_rp8_personal_access_tokens.py"
DB = "tests/integration/test_pat_store_db.py"
IMG = "tests/integration/test_migrations_image.py"
KC = "tests/integration/test_pat_keycloak.py"

# Before an owner without an organization was refused, the tenant fell back to "".
ORG_GUARD = (
    "    if not caller.organizations:\n"
    "        raise ManagementError(\n"
    "            403,\n"
    '            "organization_required",\n'
    '            "a personal access token is bound to an organization, '
    'and the owner belongs to none",\n'
    "        )\n"
)
ORG_FALLBACK = '    return caller.organizations[0] if caller.organizations else ""\n'
ORG_RETURN = "    return caller.organizations[0]\n"
MULTI_ORG = (
    "    if len(caller.organizations) > 1:\n"
    "        raise ManagementError(\n"
    "            400,\n"
    '            "invalid_request",\n'
    "            \"the owner belongs to several organizations; name one in 'organization'\",\n"
    "        )\n"
)


class Mutation(NamedTuple):
    name: str
    path: Path
    old: str
    new: str
    test: str


UNIT = [
    Mutation(
        "revoked",
        PAT,
        "        if record.revoked_at is not None:\n"
        '            raise InvalidGrant("the personal access token is revoked")\n',
        "",
        f"{RP8}::TestRP8RevokedAndExpired::test_guarded_refuses_revoked",
    ),
    Mutation(
        "expired",
        PAT,
        "        if record.expires_at <= now:\n"
        '            raise InvalidGrant("the personal access token is expired")\n',
        "",
        f"{RP8}::TestRP8RevokedAndExpired::test_guarded_refuses_expired",
    ),
    Mutation(
        "checksum",
        PAT,
        "        if not is_well_formed(subject_token):\n"
        '            raise InvalidGrant("subject_token is not a valid personal access token")\n\n'
        "        record",
        "        record",
        f"{RP8}::TestRP8ChecksumWithoutDatabase::test_guarded_refuses_bad_checksum_unasked",
    ),
    Mutation(
        "resource",
        PAT,
        "        if entry is None or entry.url not in record.resources:",
        "        if entry is None:",
        f"{RP8}::TestRP8ResourceBinding::test_guarded_token_for_x_gets_nothing_for_y",
    ),
    Mutation(
        "tenant",
        PAT,
        '    return " ".join([*scopes, f"organization:{tenant}"])',
        '    return " ".join(scopes)',
        f"{RP8}::TestRP8Tenant::test_guarded_tenant_token_requests_only_its_organization",
    ),
    Mutation(
        "org-create",
        PAT,
        ORG_GUARD + MULTI_ORG + ORG_RETURN,
        MULTI_ORG + ORG_FALLBACK,
        f"{RP8}::TestRP8Tenant::test_guarded_owner_without_an_organization_gets_no_token",
    ),
    Mutation(
        "org-exch",
        PAT,
        "        if not record.tenant:\n"
        '            raise InvalidGrant("the personal access token is not bound to an '
        'organization")\n',
        "",
        f"{RP8}::TestRP8Tenant::test_guarded_row_without_an_organization_is_never_exchanged",
    ),
    Mutation(
        "realm",
        PAT,
        "        if record.realm_issuer != self._pat.realm_issuer:\n"
        '            raise InvalidGrant("the personal access token belongs to another realm")\n',
        "",
        f"{RP8}::TestRP8Tenant::test_guarded_row_of_another_realm_is_refused",
    ),
    Mutation(
        "refresh",
        PAT,
        '        dropped = payload.pop("refresh_token", None) is not None',
        "        dropped = False",
        f"{RP8}::TestRP8NoRefreshToken::test_guarded_refresh_token_never_reaches_the_agent",
    ),
    Mutation(
        "set",
        PAT,
        "        if missing:\n            raise ManagementError(",
        "        if False:\n            raise ManagementError(",
        f"{RP8}::TestRP8SetBeyondOwner::test_guarded_set_the_owner_cannot_carry_is_refused",
    ),
    Mutation(
        "secret",
        PAT,
        '"tenant": tenant})',
        '"tenant": tenant, "value": token})',
        f"{RP8}::TestRP8SecretNowhere::test_guarded_token_value_is_in_no_row_log_or_error",
    ),
]

INTEGRATION = [
    Mutation(
        "db-owner",
        STORE,
        '"AND owner_sub = %s AND revoked_at IS NULL"',
        '"AND (owner_sub = %s OR true) AND revoked_at IS NULL"',
        f"{DB}::test_list_and_revoke_are_bound_to_realm_and_owner",
    ),
    Mutation(
        "db-grant",
        MIGRATION,
        "GRANT UPDATE (last_used_at, revoked_at)\n    ON ${flyway:defaultSchema}",
        "GRANT UPDATE\n    ON ${flyway:defaultSchema}",
        f"{DB}::test_application_role_holds_exactly_the_migration_grants",
    ),
    Mutation(
        "db-tenant",
        MIGRATION,
        "    tenant        text        NOT NULL CHECK (tenant <> ''),",
        "    tenant        text        NOT NULL,",
        f"{DB}::test_a_row_without_an_organization_cannot_exist",
    ),
    Mutation(
        "img-bypass",
        MIGRATION,
        "    IF is_super OR is_bypass THEN\n        RAISE EXCEPTION\n            'the runtime role",
        "    IF false THEN\n        RAISE EXCEPTION\n            'the runtime role",
        f"{IMG}::test_a_runtime_role_with_bypassrls_is_refused",
    ),
    Mutation(
        "img-super",
        MIGRATION,
        "    IF is_super OR is_bypass THEN\n        RAISE EXCEPTION\n"
        "            'the migrating role",
        "    IF false THEN\n        RAISE EXCEPTION\n            'the migrating role",
        f"{IMG}::test_a_superuser_migrator_is_refused",
    ),
    Mutation(
        "img-off",
        ENTRYPOINT,
        'if [ -z "$user" ] && [ -z "$password" ]; then',
        "if false; then",
        f"{IMG}::test_empty_credentials_exit_zero_and_create_nothing",
    ),
    Mutation(
        "img-rerun",
        ENTRYPOINT,
        'exec flyway "$@"',
        'flyway -cleanDisabled=false clean && exec flyway "$@"',
        f"{IMG}::test_cold_start_creates_schema_table_and_role_and_a_rerun_changes_nothing",
    ),
    Mutation(
        "behind",
        STORE,
        "        if current < latest_version():",
        "        if False:",
        f"{IMG}::test_the_proxy_does_not_start_against_an_unmigrated_schema",
    ),
    Mutation(
        "kc-set",
        PAT,
        "            scope=_scope_param(record.scopes, record.tenant),",
        "            scope=_scope_param(self._pat.scopes, record.tenant),",
        f"{KC}::test_set_without_dispatch_executor_yields_no_such_role",
    ),
    Mutation(
        "kc-trial",
        PAT,
        "        if missing:\n            raise ManagementError(",
        "        if False:\n            raise ManagementError(",
        f"{KC}::test_set_beyond_the_owner_cannot_be_created",
    ),
    Mutation(
        "kc-sid",
        PAT,
        '        if not claims.get("sid"):',
        "        if False:",
        f"{KC}::test_token_from_a_pat_cannot_manage_pats",
    ),
    Mutation(
        "kc-tenant",
        PAT,
        '    return " ".join([*scopes, f"organization:{tenant}"])',
        '    return " ".join(scopes)',
        f"{KC}::test_tenant_a_never_yields_tenant_b",
    ),
    Mutation(
        "kc-org",
        PAT,
        ORG_GUARD + MULTI_ORG + ORG_RETURN,
        MULTI_ORG + ORG_FALLBACK,
        f"{KC}::test_owner_without_an_organization_gets_no_token",
    ),
]


def run(mutation: Mutation) -> bool:
    source = mutation.path.read_text()
    if source.count(mutation.old) != 1:
        print(f"{mutation.name:10s} CANNOT APPLY: the guarded line is not found exactly once")
        return False
    mutation.path.write_text(source.replace(mutation.old, mutation.new))
    try:
        result = subprocess.run(  # noqa: S603 - fixed interpreter, fixed arguments
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "--tb=short",
                "--color=no",
                "-p",
                "no:cacheprovider",
                mutation.test,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        mutation.path.write_text(source)
    assertion = next((ln.strip() for ln in result.stdout.splitlines() if ln.startswith("E ")), "")
    red = result.returncode == 1 and " failed" in result.stdout
    verdict = "RED" if red else f"NOT RED (rc={result.returncode})"
    print(f"{mutation.name:10s} {verdict:16s} {assertion[:150]}")
    return red


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--integration", action="store_true")
    mutations = INTEGRATION if parser.parse_args().integration else UNIT
    return 0 if all([run(m) for m in mutations]) else 1


if __name__ == "__main__":
    sys.exit(main())
