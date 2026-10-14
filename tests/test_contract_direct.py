import hashlib
import json
from pathlib import Path

import pytest

CONTRACT = str(Path(__file__).parents[1] / "contracts" / "stargaze.py")
ADVISORY_ID = "GHSA-2222-3333-4444"


def advisory_json(description="Sample advisory", advisory_id=ADVISORY_ID, package_name="sample-package",
                  ecosystem="npm", updated_at="2026-04-01T23:51:13Z", published_at="2026-03-31T10:00:00Z"):
    return json.dumps({
        "ghsa_id": advisory_id, "summary": "Sample advisory", "description": description,
        "published_at": published_at, "updated_at": updated_at,
        "vulnerabilities": [{"package": {"ecosystem": ecosystem, "name": package_name},
                             "vulnerable_version_range": "<2.0.0"}],
    }, separators=(",", ":"))


def revision_for(body, provider="ghsa"):
    return provider + "-sha256:" + hashlib.sha256(body.encode()).hexdigest()


def mock_advisory(direct_vm, pattern, response, advisory_id=ADVISORY_ID, package_name="sample-package",
                  updated_at="2026-04-01T23:51:13Z", description=None):
    response = dict(response)
    if response.get("status") == 200:
        desc = description if description is not None else response.get("body", "")
        response["body"] = advisory_json(desc, advisory_id=advisory_id, package_name=package_name,
                                         updated_at=updated_at)
    direct_vm.mock_web(pattern, response)
    return response.get("body", "")


def setup_contract(direct_vm, direct_deploy, direct_owner):
    direct_vm.strict_mocks = False
    contract = direct_deploy(CONTRACT)
    contract.authorize_source_host("api.github.com", "PRIMARY")
    return contract


def add_release(contract, direct_owner, version="1.0.0", predecessor=""):
    owner_hex = getattr(direct_owner, "as_hex", None) or "0x" + bytes(direct_owner).hex()
    return contract.register_release(
        "sample/project", "https://github.com/sample/project", owner_hex, version,
        "a" * 40, ("b" if version == "1.0.0" else "c") * 64, "npm", "sample-package",
        "d" * 64, predecessor,
    )


def add_assessment(contract, release_id, revision=None, advisory_id=ADVISORY_ID):
    body = advisory_json()
    commitment = revision or revision_for(body)
    sources = [{"url": "https://api.github.com/advisories/" + advisory_id, "role": "PRIMARY"}]
    return contract.register_assessment(release_id, advisory_id, commitment, "Sample advisory",
                                        "npm", "sample-package", "stargaze-policy-v2",
                                        json.dumps(sources, separators=(",", ":")))


def matching_mock(direct_vm, description="Sample advisory", advisory_id=ADVISORY_ID,
                  package_name="sample-package", updated_at="2026-04-01T23:51:13Z"):
    body = advisory_json(description, advisory_id, package_name, updated_at=updated_at)
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": body})
    return revision_for(body)


def test_release_identity_is_immutable_and_duplicate_rejected(direct_vm, direct_deploy, direct_owner):
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    release_id = add_release(contract, direct_owner)
    assert contract.get_release(release_id)["status"] == "SEALED"
    with direct_vm.expect_revert("Duplicate immutable release identity"):
        add_release(contract, direct_owner)


def test_arbitrary_revision_label_is_rejected(direct_vm, direct_deploy, direct_owner):
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    with direct_vm.expect_revert("provider-prefixed SHA-256"):
        add_assessment(contract, add_release(contract, direct_owner), "latest")


def test_approved_host_unrelated_path_and_source_spoof_are_rejected(direct_vm, direct_deploy, direct_owner):
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    release_id = add_release(contract, direct_owner)
    with direct_vm.expect_revert("canonical endpoint for the frozen advisory ID"):
        contract.register_assessment(release_id, ADVISORY_ID, revision_for(advisory_json()), "Title", "npm",
                                     "sample-package", "p1", '[{"url":"https://api.github.com/repos/x/y/releases/latest","role":"PRIMARY"}]')
    with direct_vm.expect_revert("Invalid source URL"):
        contract.register_assessment(release_id, ADVISORY_ID, revision_for(advisory_json()), "Title", "npm",
                                     "sample-package", "p1", '[{"url":"https://github.com@evil.example/x","role":"PRIMARY"}]')
    assert contract.get_assessment_counter() == 0


def test_only_release_owner_can_reserve_assessment_identity(direct_vm, direct_deploy, direct_owner, direct_charlie):
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    release_id = add_release(contract, direct_owner)
    sources = json.dumps([{"url": "https://api.github.com/advisories/" + ADVISORY_ID, "role": "PRIMARY"}])
    with direct_vm.prank(direct_charlie):
        with direct_vm.expect_revert("Only the sealed release owner"):
            contract.register_assessment(release_id, ADVISORY_ID, revision_for(advisory_json()), "Attacker",
                                         "npm", "sample-package", "attacker-policy", sources)
    assessment_id = add_assessment(contract, release_id)
    assert assessment_id == "asm-1"
    with direct_vm.expect_revert("Assessment identity already exists"):
        add_assessment(contract, release_id)


def test_accurate_ghsa_body_is_cryptographically_authenticated(direct_vm, direct_deploy, direct_owner):
    body = advisory_json("affects versions below 2.0.0")
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "AFFECTED")
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    release_id = add_release(contract, direct_owner)
    assessment_id = add_assessment(contract, release_id, revision_for(body))
    assert contract.evaluate_assessment(assessment_id) == "AFFECTED"
    record = contract.get_assessment(assessment_id)
    assert record["revision_authenticated"] is True
    assert record["revision"] == revision_for(body)
    assert record["revision_metadata"] == {"published_at": "2026-03-31T10:00:00Z", "updated_at": "2026-04-01T23:51:13Z"}


def test_false_content_commitment_is_terminal_and_never_authorizes(direct_vm, direct_deploy, direct_owner):
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": advisory_json("changed")})
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    release_id = add_release(contract, direct_owner)
    assessment_id = add_assessment(contract, release_id, revision_for(advisory_json("original")))
    assert contract.evaluate_assessment(assessment_id) == "INVALID_REVISION"
    record = contract.get_assessment(assessment_id)
    assert record["state"] == "INVALID_REVISION" and not record["revision_authenticated"]
    assert contract.authorization_for_release(release_id, json.dumps([{"advisory_id": ADVISORY_ID, "revision": record["revision"]}]))["status"] == "HOLD"


@pytest.mark.parametrize("bad_body", [
    advisory_json("x", advisory_id="GHSA-3333-4444-5555"),
    advisory_json("x", package_name="other-package"),
    json.dumps({"ghsa_id": ADVISORY_ID, "vulnerabilities": []}, separators=(",", ":")),
    advisory_json("x", updated_at=""),
])
def test_advisory_identifier_package_or_revision_metadata_must_match(direct_vm, direct_deploy, direct_owner, bad_body):
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": bad_body})
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    release_id = add_release(contract, direct_owner)
    assessment_id = add_assessment(contract, release_id, revision_for(bad_body))
    assert contract.evaluate_assessment(assessment_id) == "INVALID_REVISION"
    assert not contract.get_assessment(assessment_id)["eligible"]


def test_changed_body_with_same_identifier_and_updated_at_is_detected(direct_vm, direct_deploy, direct_owner):
    old = advisory_json("vulnerability scope A")
    new = advisory_json("vulnerability scope B")
    assert json.loads(old)["updated_at"] == json.loads(new)["updated_at"]
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": new})
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    assessment_id = add_assessment(contract, add_release(contract, direct_owner), revision_for(old))
    assert contract.evaluate_assessment(assessment_id) == "INVALID_REVISION"


def test_temporary_http_failure_is_retryable_and_recovery_preserves_identity(direct_vm, direct_deploy, direct_owner):
    body = advisory_json("fixed before 1.0.0")
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 503, "body": "unavailable"})
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    release_id = add_release(contract, direct_owner)
    revision = revision_for(body)
    assessment_id = add_assessment(contract, release_id, revision)
    assert contract.evaluate_assessment(assessment_id) == "RETRYABLE_FAILURE"
    first = contract.get_assessment_attempt(assessment_id, 1)
    assert first["failure_reason"] == "HTTP_UNAVAILABLE_OR_INCOMPLETE_SOURCE"
    direct_vm.clear_mocks()
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "NOT_AFFECTED")
    assert contract.evaluate_assessment(assessment_id) == "NOT_AFFECTED"
    record = contract.get_assessment(assessment_id)
    assert record["id"] == assessment_id and record["revision"] == revision and record["attempt_count"] == 2
    assert [attempt["sequence"] for attempt in contract.list_assessment_attempts(assessment_id, 0, 3)] == [1, 2]


def test_malformed_model_output_is_retryable_but_valid_conditional_is_final(direct_vm, direct_deploy, direct_owner):
    body = advisory_json("ambiguous scope")
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "NOT_AFFECTED.")
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    assessment_id = add_assessment(contract, add_release(contract, direct_owner), revision_for(body))
    assert contract.evaluate_assessment(assessment_id) == "RETRYABLE_FAILURE"
    direct_vm.clear_mocks()
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "CONDITIONAL")
    assert contract.evaluate_assessment(assessment_id) == "CONDITIONAL"
    with direct_vm.expect_revert("not eligible for another attempt"):
        contract.evaluate_assessment(assessment_id)


def test_final_affected_verdict_cannot_be_retried_for_verdict_shopping(direct_vm, direct_deploy, direct_owner):
    body = advisory_json("affected below 2.0.0")
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "AFFECTED")
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    assessment_id = add_assessment(contract, add_release(contract, direct_owner), revision_for(body))
    assert contract.evaluate_assessment(assessment_id) == "AFFECTED"
    with direct_vm.expect_revert("not eligible for another attempt"):
        contract.evaluate_assessment(assessment_id)


def test_attempt_history_is_append_only_bounded_and_replay_safe(direct_vm, direct_deploy, direct_owner):
    body = advisory_json()
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 429, "body": "slow down"})
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    assessment_id = add_assessment(contract, add_release(contract, direct_owner), revision_for(body))
    for expected in ("RETRYABLE_FAILURE", "RETRYABLE_FAILURE", "RETRYABLE_FAILURE"):
        assert contract.evaluate_assessment(assessment_id) == expected
    with direct_vm.expect_revert("attempt limit reached"):
        contract.evaluate_assessment(assessment_id)
    attempts = contract.list_assessment_attempts(assessment_id, 0, 3)
    assert [item["id"] for item in attempts] == [assessment_id + "/attempt-1", assessment_id + "/attempt-2", assessment_id + "/attempt-3"]
    assert [item["sequence"] for item in attempts] == [1, 2, 3]


def test_manifest_commitments_and_packet_digest_are_reconstructible(direct_vm, direct_deploy, direct_owner):
    body = advisory_json("fixed before 1.0.0")
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "NOT_AFFECTED")
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    release_id = add_release(contract, direct_owner)
    assessment_id = add_assessment(contract, release_id, revision_for(body))
    contract.evaluate_assessment(assessment_id)
    record = contract.get_assessment(assessment_id)
    attempt = contract.get_assessment_attempt(assessment_id, 1)
    source = attempt["manifest"][0]
    assert source["url"].endswith(ADVISORY_ID)
    assert source["response_status"] == 200 and source["body_bytes"] == len(body.encode())
    assert source["body_sha256"] == hashlib.sha256(body.encode()).hexdigest()
    assert source["metadata_identity_valid"] and source["revision_authenticated"]
    packet = {"domain": "STARGAZE_EVIDENCE_PACKET_V2", "attempt_id": attempt["id"], "attempt_sequence": 1,
              "release": contract.get_release(release_id),
              "advisory": {"id": record["advisory_id"], "revision": record["revision"],
                           "ecosystem": record["ecosystem"], "package": record["package_name"],
                           "policy": record["policy_version"], "metadata": record["revision_metadata"]},
              "sources": attempt["manifest"], "complete": True, "revision_authenticated": True,
              "state": "DECIDED", "failure_reason": "", "verdict": "NOT_AFFECTED"}
    replay_digest = hashlib.sha256(json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert replay_digest == record["packet_digest"] == attempt["packet_digest"]
    corrupted = dict(packet)
    corrupted["sources"] = [dict(source, body_sha256="0" * 64)]
    assert hashlib.sha256(json.dumps(corrupted, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != replay_digest


def test_revocation_before_evaluation_suspends_and_reauthorization_does_not_restore(direct_vm, direct_deploy, direct_owner):
    body = advisory_json()
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": body})
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    assessment_id = add_assessment(contract, add_release(contract, direct_owner), revision_for(body))
    contract.revoke_source_host("api.github.com", "PRIMARY")
    assert contract.evaluate_assessment(assessment_id) == "SUSPENDED"
    contract.authorize_source_host("api.github.com", "PRIMARY")
    with direct_vm.expect_revert("not eligible for another attempt"):
        contract.evaluate_assessment(assessment_id)


def test_revocation_after_approval_holds_current_authorization(direct_vm, direct_deploy, direct_owner):
    body = advisory_json("fixed before 1.0.0")
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "NOT_AFFECTED")
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    release_id = add_release(contract, direct_owner)
    assessment_id = add_assessment(contract, release_id, revision_for(body))
    contract.evaluate_assessment(assessment_id)
    required = json.dumps([{"advisory_id": ADVISORY_ID, "revision": revision_for(body)}])
    assert contract.authorization_for_release(release_id, required)["status"] == "AUTHORIZED_FOR_POLICY_SET"
    contract.revoke_source_host("api.github.com", "PRIMARY")
    assert contract.authorization_for_release(release_id, required)["status"] == "HOLD"
    contract.authorize_source_host("api.github.com", "PRIMARY")
    assert contract.authorization_for_release(release_id, required)["status"] == "HOLD"


def test_revocation_after_failed_attempt_blocks_retry(direct_vm, direct_deploy, direct_owner):
    body = advisory_json()
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 503, "body": "offline"})
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    assessment_id = add_assessment(contract, add_release(contract, direct_owner), revision_for(body))
    assert contract.evaluate_assessment(assessment_id) == "RETRYABLE_FAILURE"
    contract.revoke_source_host("api.github.com", "PRIMARY")
    assert contract.evaluate_assessment(assessment_id) == "SUSPENDED"
    assert contract.get_assessment(assessment_id)["attempt_count"] == 2


def test_authorization_requires_exact_complete_authenticated_revision(direct_vm, direct_deploy, direct_owner):
    body = advisory_json("fixed before 1.0.0")
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "NOT_AFFECTED")
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    release_id = add_release(contract, direct_owner)
    assessment_id = add_assessment(contract, release_id, revision_for(body))
    contract.evaluate_assessment(assessment_id)
    good = {"advisory_id": ADVISORY_ID, "revision": revision_for(body)}
    assert contract.authorization_for_release(release_id, json.dumps([good]))["checks"][0]["assessment_id"] == assessment_id
    assert contract.authorization_for_release(release_id, json.dumps([dict(good, revision="ghsa-sha256:" + "0" * 64)]))["status"] == "HOLD"
    assert contract.authorization_for_release(release_id, json.dumps([good, good]))["reason"] == "DUPLICATE_POLICY_ENTRY"


def test_multiple_advisories_on_one_release_are_enforced_as_a_complete_policy(direct_vm, direct_deploy, direct_owner):
    second_id = "GHSA-3333-4444-5555"
    first_body = advisory_json("fixed before 1.0.0", ADVISORY_ID)
    second_body = advisory_json("fixed before 1.0.0", second_id)
    direct_vm.mock_web(r"api\.github\.com/advisories/GHSA-2222-3333-4444", {"status": 200, "body": first_body})
    direct_vm.mock_web(r"api\.github\.com/advisories/GHSA-3333-4444-5555", {"status": 200, "body": second_body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "NOT_AFFECTED")
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    release_id = add_release(contract, direct_owner)
    first = add_assessment(contract, release_id, revision_for(first_body))
    second = add_assessment(contract, release_id, revision_for(second_body), second_id)
    contract.evaluate_assessment(first)
    contract.evaluate_assessment(second)
    required = [{"advisory_id": ADVISORY_ID, "revision": revision_for(first_body)},
                {"advisory_id": second_id, "revision": revision_for(second_body)}]
    result = contract.authorization_for_release(release_id, json.dumps(required))
    assert result["status"] == "AUTHORIZED_FOR_POLICY_SET" and len(result["checks"]) == 2
    required[1]["revision"] = "ghsa-sha256:" + "0" * 64
    assert contract.authorization_for_release(release_id, json.dumps(required))["status"] == "HOLD"


def test_conditional_and_insufficient_evidence_never_authorize(direct_vm, direct_deploy, direct_owner):
    body = advisory_json("unclear scope")
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "CONDITIONAL")
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    release_id = add_release(contract, direct_owner)
    assessment_id = add_assessment(contract, release_id, revision_for(body))
    assert contract.evaluate_assessment(assessment_id) == "CONDITIONAL"
    required = json.dumps([{"advisory_id": ADVISORY_ID, "revision": revision_for(body)}])
    assert contract.authorization_for_release(release_id, required)["status"] == "HOLD"


def test_one_to_four_sources_are_sorted_and_fully_manifested(direct_vm, direct_deploy, direct_owner):
    advisory_body = advisory_json("affected below 2.0.0")
    registry_body = json.dumps({"name": "sample-package", "version": "1.0.0"})
    commit = "a" * 40
    repo_url = "https://github.com/sample/project"
    commit_body = json.dumps({"sha": commit, "html_url": repo_url + "/commit/" + commit})
    osv_body = json.dumps({"id": ADVISORY_ID, "modified": "2026-04-01T23:51:13Z", "affected": [{"package": {"ecosystem": "npm", "name": "sample-package"}}]})
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": advisory_body})
    direct_vm.mock_web(r"registry\.npmjs\.org/sample-package/1\.0\.0", {"status": 200, "body": registry_body})
    direct_vm.mock_web(r"api\.github\.com/repos/sample/project/commits/", {"status": 200, "body": commit_body})
    direct_vm.mock_web(r"api\.osv\.dev/v1/vulns/", {"status": 200, "body": osv_body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "AFFECTED")
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    for host in ("api.github.com", "api.osv.dev", "registry.npmjs.org"):
        contract.authorize_source_host(host, "SUPPLEMENTAL")
    release_id = add_release(contract, direct_owner)
    urls = [
        ("https://api.github.com/advisories/" + ADVISORY_ID, "PRIMARY"),
        ("https://api.github.com/repos/sample/project/commits/" + commit, "SUPPLEMENTAL"),
        ("https://api.osv.dev/v1/vulns/" + ADVISORY_ID, "SUPPLEMENTAL"),
        ("https://registry.npmjs.org/sample-package/1.0.0", "SUPPLEMENTAL"),
    ]
    assessment_id = contract.register_assessment(release_id, ADVISORY_ID, revision_for(advisory_body), "Sample advisory", "npm",
                                                 "sample-package", "p1", json.dumps([{"url": u, "role": r} for u, r in urls]))
    assert contract.evaluate_assessment(assessment_id) == "AFFECTED"
    manifest = contract.get_assessment(assessment_id)["evidence_manifest"]
    assert len(manifest) == 4 and [item["url"] for item in manifest] == sorted(u for u, _ in urls)


@pytest.mark.parametrize("registry_size", [100, 500])
def test_indexed_policy_does_not_depend_on_unrelated_registry_records(direct_vm, direct_deploy, direct_owner, registry_size):
    body = advisory_json("fixed before 1.0.0")
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "NOT_AFFECTED")
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    release_id = add_release(contract, direct_owner)
    revision = revision_for(body)
    assessment_id = add_assessment(contract, release_id, revision)
    contract.evaluate_assessment(assessment_id)
    for number in range(registry_size):
        # Many revisions of the same advisory are valid distinct indexed identities and are never fetched by this view.
        add_assessment(contract, release_id, "ghsa-sha256:" + format(number + 1, "064x"))
    result = contract.authorization_for_release(release_id, json.dumps([{"advisory_id": ADVISORY_ID, "revision": revision}]))
    assert result["status"] == "AUTHORIZED_FOR_POLICY_SET" and result["checks"][0]["assessment_id"] == assessment_id


def test_osv_primary_uses_provider_specific_content_revision(direct_vm, direct_deploy, direct_owner):
    body = json.dumps({"id": "OSV-2026-1234", "aliases": [ADVISORY_ID], "published": "2026-03-31T10:00:00Z",
                       "modified": "2026-04-01T23:51:13Z", "affected": [{"package": {"ecosystem": "npm", "name": "sample-package"}}]}, separators=(",", ":"))
    direct_vm.mock_web(r"api\.osv\.dev/v1/vulns/", {"status": 200, "body": body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "NOT_AFFECTED")
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    contract.authorize_source_host("api.osv.dev", "PRIMARY")
    release_id = add_release(contract, direct_owner)
    revision = revision_for(body, "osv")
    assessment_id = contract.register_assessment(release_id, ADVISORY_ID, revision, "OSV title", "npm", "sample-package", "p1",
        json.dumps([{"url": "https://api.osv.dev/v1/vulns/" + ADVISORY_ID, "role": "PRIMARY"}]))
    assert contract.evaluate_assessment(assessment_id) == "NOT_AFFECTED"
    assessment = contract.get_assessment(assessment_id)
    assert assessment["revision_authenticated"] is True
    assert assessment["revision_metadata"]["modified"] == "2026-04-01T23:51:13Z"


def test_successor_keeps_predecessor_assessment_historical(direct_vm, direct_deploy, direct_owner):
    body = advisory_json("affects versions below 2.0.0")
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "AFFECTED")
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    original = add_release(contract, direct_owner)
    original_assessment = add_assessment(contract, original, revision_for(body))
    contract.evaluate_assessment(original_assessment)
    successor = add_release(contract, direct_owner, "2.0.0", original)
    assert [entry["id"] for entry in contract.get_release_lineage(successor)] == [original, successor]
    assert contract.get_assessment(original_assessment)["verdict"] == "AFFECTED"


def test_independent_validator_recomputes_commitment_and_rejects_substitution(direct_vm, direct_deploy, direct_owner):
    body = advisory_json("affected below 2.0.0")
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": body})
    direct_vm.mock_llm(r"Authenticated advisory identity", "AFFECTED")
    contract = setup_contract(direct_vm, direct_deploy, direct_owner)
    assessment_id = add_assessment(contract, add_release(contract, direct_owner), revision_for(body))
    assert contract.evaluate_assessment(assessment_id) == "AFFECTED"
    assert direct_vm.run_validator() is True
    direct_vm.clear_mocks()
    direct_vm.mock_web(r"api\.github\.com/advisories/", {"status": 200, "body": advisory_json("different evidence")})
    direct_vm.mock_llm(r"Authenticated advisory identity", "AFFECTED")
    assert direct_vm.run_validator() is False
    fake = json.dumps({"attempt_id": "asm-1/attempt-1", "attempt_sequence": 1, "state": "DECIDED",
                       "failure_reason": "", "verdict": "NOT_AFFECTED", "packet_digest": "a" * 64,
                       "manifest": [], "complete": True, "revision_authenticated": True,
                       "revision_metadata": {}, "trust_epoch_valid": True}, sort_keys=True, separators=(",", ":"))
    assert direct_vm.run_validator(leader_result=fake) is False
