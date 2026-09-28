from citius_ui.mock_engine import (
    artifact_rows,
    consumer_request_for_artifact,
    execute,
    history_rows,
    initial_state,
    producer_response_rows,
    request_example,
    run_scenario_step,
)


def test_complete_identity_scenario_records_success_and_expected_denials():
    state = initial_state()
    sequence = [
        "CISO",
        "Producer",
        "Producer",
        "Producer",
        "Consumer",
        "Consumer",
        "Producer",
        "CISO",
        "Consumer",
    ]

    for persona in sequence:
        state, _, _ = run_scenario_step(state, persona)

    assert state["scenario_step"] == len(sequence)
    assert len(state["history"]) == len(sequence)
    statuses = [record["status"] for record in state["history"]]
    assert statuses == [
        "OK",
        "OK",
        "OK",
        "PERMISSION_DENIED",
        "OK",
        "PERMISSION_DENIED",
        "PERMISSION_DENIED",
        "OK",
        "OK",
    ]
    assert state["keys"]["demo-signing-key"]["template_id"] == "ml-dsa-65"
    assert state["history"][-1]["result"]["response"]["valid"] is True
    assert "historical key version 1" in state["history"][-1]["result"]["response"]["compatibility"]


def test_wrong_persona_does_not_advance_scenario():
    state, result, complete = run_scenario_step(initial_state(), "Producer")

    assert result["status"] == "IDENTITY_SWITCH_REQUIRED"
    assert state["scenario_step"] == 0
    assert not complete
    assert not state["history"]


def test_resource_deny_takes_precedence_for_an_allowed_method():
    state, result = execute(
        initial_state(),
        "Producer",
        "CryptoService",
        "Sign",
        {"key_name": "demo-restricted-key", "message": "test"},
    )

    assert result["status"] == "PERMISSION_DENIED"
    assert result["error"]["category"] == "resource_pattern"
    assert history_rows(state)[0][5] == "PERMISSION_DENIED"


def test_contract_method_can_be_visible_while_unimplemented():
    state, result = execute(
        initial_state(),
        "CISO",
        "KeyManagementService",
        "RotateKey",
        {"name": "demo-key"},
    )

    assert result["status"] == "UNIMPLEMENTED"
    assert state["history"][0]["method"] == "RotateKey"


def test_signature_artifact_retains_metadata_and_verifies_after_transform():
    state = initial_state()
    state, _ = execute(
        state,
        "CISO",
        "CryptoPolicyService",
        "CreateCryptoPolicy",
        {"name": "demo-policy", "policy_document": {}},
    )
    state, _ = execute(
        state,
        "Producer",
        "KeyManagementService",
        "CreateKey",
        {"name": "demo-key", "policy": "demo-policy", "template_id": "ecdsa-p256-sha256"},
    )
    state, signed = execute(
        state,
        "Producer",
        "CryptoService",
        "Sign",
        {"key_name": "demo-key", "message": "long-lived payload"},
    )
    state, _ = execute(
        state,
        "CISO",
        "KeyManagementService",
        "TransformKey",
        {"name": "demo-key", "template_id": "ml-dsa-65", "retain_key_bytes": False},
    )

    state, without_metadata = execute(
        state,
        "Consumer",
        "CryptoService",
        "Verify",
        {
            "key_name": "demo-key",
            "message": "long-lived payload",
            "signature": signed["response"]["signature"],
        },
    )
    method, request = consumer_request_for_artifact(state, "artifact-001")
    state, with_metadata = execute(state, "Consumer", "CryptoService", method, request)

    assert without_metadata["response"]["valid"] is False
    assert with_metadata["response"]["valid"] is True
    assert with_metadata["response"]["metadata"]["key_version"] == 1
    assert artifact_rows(state)[0][5] == 1


def test_ciphertext_artifact_retains_metadata_and_decrypts_after_transform():
    state = initial_state()
    state, _ = execute(
        state,
        "CISO",
        "CryptoPolicyService",
        "CreateCryptoPolicy",
        {"name": "demo-policy", "policy_document": {}},
    )
    state, _ = execute(
        state,
        "Producer",
        "KeyManagementService",
        "CreateKey",
        {"name": "demo-cipher-key", "policy": "demo-policy", "template_id": "aes-256-gcm"},
    )
    state, _ = execute(
        state,
        "Producer",
        "CryptoService",
        "Encrypt",
        {
            "key_name": "demo-cipher-key",
            "plaintext": "archived secret",
            "additional_authenticated_data": "tenant=demo",
        },
    )
    state, _ = execute(
        state,
        "CISO",
        "KeyManagementService",
        "TransformKey",
        {"name": "demo-cipher-key", "template_id": "aes-256-gcm-v2"},
    )

    method, request = consumer_request_for_artifact(state, "artifact-001")
    state, decrypted = execute(state, "Consumer", "CryptoService", method, request)

    assert method == "Decrypt"
    assert decrypted["response"]["plaintext"] == "archived secret"
    assert "historical key version 1" in decrypted["response"]["compatibility"]


def test_producer_response_history_appends_key_name_and_complete_metadata_bundle():
    state = initial_state()
    state["keys"]["demo-key"] = {"version": 3}

    state, signed = execute(
        state,
        "Producer",
        "CryptoService",
        "Sign",
        {"key_name": "demo-key", "message": "first"},
    )
    state, encrypted = execute(
        state,
        "Producer",
        "CryptoService",
        "Encrypt",
        {"key_name": "demo-key", "plaintext": "second"},
    )

    rows = producer_response_rows(state)
    assert len(rows) == 2
    assert rows[0][2:5] == ["Signature", "demo-key", 3]
    assert rows[1][2:5] == ["Ciphertext", "demo-key", 3]
    assert '"key_version": 3' in rows[0][5]
    assert signed["response"]["signature"] in rows[0][5]
    assert encrypted["response"]["ciphertext"] in rows[1][5]


def _mock_with_key(persona: str = "CISO") -> dict:
    state = initial_state()
    state, _ = execute(
        state,
        persona,
        "CryptoPolicyService",
        "CreateCryptoPolicy",
        request_example("CryptoPolicyService", "CreateCryptoPolicy"),
    )
    state, _ = execute(
        state, persona, "KeyManagementService", "CreateKey", request_example("KeyManagementService", "CreateKey")
    )
    return state


def test_migrate_key_moves_the_key_and_records_a_version():
    state = _mock_with_key()
    state, check = execute(
        state,
        "CISO",
        "KeyManagementService",
        "ValidateKeyOperation",
        {"name": "demo-signing-key", "target_instance_id": "openssl"},
    )
    assert check["status"] == "OK"
    assert check["response"]["recommended_strategy"] == "MIGRATION_STRATEGY_PROVIDER_SWITCH"

    state, moved = execute(
        state, "CISO", "KeyManagementService", "MigrateKey", request_example("KeyManagementService", "MigrateKey")
    )
    assert moved["status"] == "OK"
    assert moved["response"]["key_metadata"]["provider"] == "openssl"
    assert moved["response"]["result"]["key_bytes_preserved"] is True
    assert "archived_key_info" not in moved["response"]
    assert state["keys"]["demo-signing-key"]["version"] == 2

    _, again = execute(
        state, "CISO", "KeyManagementService", "MigrateKey", request_example("KeyManagementService", "MigrateKey")
    )
    assert again["status"] == "FAILED_PRECONDITION"


def test_rekey_and_archive_reports_the_archived_version():
    state, moved = execute(
        _mock_with_key(),
        "CISO",
        "KeyManagementService",
        "MigrateKey",
        {"name": "demo-signing-key", "strategy": "REKEY_AND_ARCHIVE", "target_instance_id": "openssl"},
    )
    assert moved["status"] == "OK"
    assert moved["response"]["result"]["key_bytes_preserved"] is False
    assert moved["response"]["result"]["source_provider_id"] == "software"
    assert moved["response"]["archived_key_info"] == {
        "archived_key_name": "demo-signing-key",
        "provider_id": "software",
    }


def test_migrate_key_refuses_unknown_targets_and_strategies():
    state = _mock_with_key()
    _, unknown = execute(
        state,
        "CISO",
        "KeyManagementService",
        "MigrateKey",
        {"name": "demo-signing-key", "strategy": "PROVIDER_SWITCH", "target_instance_id": "hsm"},
    )
    assert unknown["status"] == "NOT_FOUND"
    _, strategy = execute(
        state,
        "CISO",
        "KeyManagementService",
        "MigrateKey",
        {"name": "demo-signing-key", "strategy": "WRAPPED_TRANSFER", "target_instance_id": "openssl"},
    )
    assert strategy["status"] == "UNIMPLEMENTED"


def test_list_keys_leaves_out_keys_the_persona_may_not_read():
    state = _mock_with_key()
    # CISO may read demo-* keys only.
    state["keys"]["prod-signing-key"] = dict(state["keys"]["demo-signing-key"], name="prod-signing-key")
    _, listed = execute(state, "CISO", "KeyManagementService", "ListKeys", {})
    assert listed["status"] == "OK"
    assert [k["name"] for k in listed["response"]["keys"]] == ["demo-signing-key"]


def test_read_key_returns_the_requested_version():
    state, _ = execute(
        _mock_with_key(),
        "CISO",
        "KeyManagementService",
        "MigrateKey",
        request_example("KeyManagementService", "MigrateKey"),
    )
    _, first = execute(state, "CISO", "KeyManagementService", "ReadKey", {"name": "demo-signing-key", "version": 1})
    assert first["response"]["key_metadata"]["provider"] == "software"
    _, current = execute(state, "CISO", "KeyManagementService", "ReadKey", {"name": "demo-signing-key"})
    assert current["response"]["key_metadata"]["provider"] == "openssl"
    _, missing = execute(state, "CISO", "KeyManagementService", "ReadKey", {"name": "demo-signing-key", "version": 9})
    assert missing["status"] == "NOT_FOUND"
