from __future__ import annotations

import json

import grpc
import pytest
import pytest_asyncio
from citius_api.messages.signing_pb2 import (
    DigestSignResponse,
    DigestVerifyResponse,
    SignResponse,
    VerifyResponse,
)
from citius_api.services.crypto_service_pb2_grpc import (
    CryptoServiceServicer,
    add_CryptoServiceServicer_to_server,
)
from citius_api.types.algorithm_params_pb2 import HashAlgorithm

from citius_ui.actions.executor import ActionExecutor, ExecutionContext
from citius_ui.actions.model import ResultStatus
from citius_ui.config import AppConfig
from citius_ui.grpc_client.client import CitiusClients
from citius_ui.history.memory_store import MemoryHistoryStore
from citius_ui.workbench.actions import build_registry


class FakeCrypto(CryptoServiceServicer):
    async def Sign(self, request, context):  # noqa: N802
        if dict(context.invocation_metadata()).get("authorization") is None:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "no token")
        response = SignResponse(signature=b"sig:" + request.input)
        response.metadata.key_version = 5
        response.metadata.api_version = "v1"
        return response

    async def Verify(self, request, context):  # noqa: N802
        valid = request.signature == b"sig:" + request.input and request.metadata.key_version == 5
        return VerifyResponse(valid=valid)

    async def DigestSign(self, request, context):  # noqa: N802
        # Like the server: record the digest's hash in the metadata, which
        # DigestVerify reads back.
        response = DigestSignResponse(signature=b"digestsig:" + request.digest)
        response.metadata.key_version = 5
        response.metadata.digest_hash = request.hash_algorithm
        return response

    async def DigestVerify(self, request, context):  # noqa: N802
        if request.metadata.digest_hash != HashAlgorithm.HASH_ALGORITHM_SHA256:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "metadata.digest_hash is required")
        valid = request.signature == b"digestsig:" + request.digest and request.metadata.key_version == 5
        return DigestVerifyResponse(valid=valid)


@pytest_asyncio.fixture
async def crypto_endpoint():
    server = grpc.aio.server()
    add_CryptoServiceServicer_to_server(FakeCrypto(), server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        yield f"127.0.0.1:{port}"
    finally:
        await server.stop(grace=None)


@pytest.mark.asyncio
async def test_sign_then_verify_through_full_stack(crypto_endpoint) -> None:
    config = AppConfig(
        citius_endpoint=crypto_endpoint,
        citius_tls_enabled=False,
        session_cookie_secure=False,
    )

    async def token() -> str:
        return "demo-token"

    clients = CitiusClients(config, token)
    registry = build_registry(clients)
    history = MemoryHistoryStore()
    executor = ActionExecutor(history)
    context = ExecutionContext(session_id="hist-1", subject="citius-producer")

    sign_result, sign_record = await executor.execute(
        registry.get("CryptoService", "Sign"),
        context,
        {"key_name": "demo-signing-key", "message": "Hello"},
    )
    assert sign_result.status is ResultStatus.OK
    signature = sign_result.response["signature"]["base64"]
    metadata = sign_result.response["metadata"]
    assert metadata["key_version"] == 5
    assert sign_record.artifacts[0].value == signature

    verify_result, _ = await executor.execute(
        registry.get("CryptoService", "Verify"),
        context,
        {
            "key_name": "demo-signing-key",
            "message": "Hello",
            "signature": signature,
            "metadata": metadata,
        },
    )
    assert verify_result.status is ResultStatus.OK
    assert verify_result.response["valid"] is True

    assert len(history.list("hist-1")) == 2
    await clients.close()


@pytest.mark.asyncio
async def test_digest_sign_bundle_carries_the_digest_for_digest_verify(crypto_endpoint) -> None:
    # Regression test: DigestSign's artifact used to reuse Sign's context
    # builder, which reads request["message"] -- a key DigestSign requests
    # never have -- so the copyable bundle silently carried an empty
    # "message" instead of the digest, and pasting it into DigestVerify left
    # the digest field empty.
    config = AppConfig(
        citius_endpoint=crypto_endpoint,
        citius_tls_enabled=False,
        session_cookie_secure=False,
    )

    async def token() -> str:
        return "demo-token"

    clients = CitiusClients(config, token)
    registry = build_registry(clients)
    history = MemoryHistoryStore()
    executor = ActionExecutor(history)
    context = ExecutionContext(session_id="hist-2", subject="citius-producer")

    digest = "8f434346"
    sign_result, sign_record = await executor.execute(
        registry.get("CryptoService", "DigestSign"),
        context,
        {"key_name": "demo-signing-key", "digest": digest, "hash_algorithm": "SHA256"},
    )
    assert sign_result.status is ResultStatus.OK
    bundle = sign_record.artifacts[0].bundle()
    assert bundle["digest"] == digest
    assert "message" not in bundle
    # The digest hash must survive the JSON bundle: DigestVerify reads it
    # from the metadata.
    assert bundle["metadata"]["digest_hash"] == "HASH_ALGORITHM_SHA256"

    # The bundle is exactly what the Workbench's bundle-paste flow hands to
    # DigestVerify (see the bundle-string test below for that path).
    verify_result, _ = await executor.execute(
        registry.get("CryptoService", "DigestVerify"),
        context,
        {
            "key_name": bundle["key_name"],
            "digest": bundle["digest"],
            "signature": bundle["signature"],
            "metadata": bundle["metadata"],
        },
    )
    assert verify_result.status is ResultStatus.OK
    assert verify_result.response["valid"] is True
    await clients.close()


@pytest.mark.asyncio
async def test_pasting_a_bundle_string_drives_digest_verify(crypto_endpoint) -> None:
    # Bundle-first flow: the user pastes the producer's copyable bundle JSON
    # into DigestVerify's single "bundle" field and runs. The server merges
    # the bundle into digest/signature/metadata without any split inputs.
    config = AppConfig(
        citius_endpoint=crypto_endpoint,
        citius_tls_enabled=False,
        session_cookie_secure=False,
    )

    async def token() -> str:
        return "demo-token"

    clients = CitiusClients(config, token)
    registry = build_registry(clients)
    history = MemoryHistoryStore()
    executor = ActionExecutor(history)
    context = ExecutionContext(session_id="hist-3", subject="citius-producer")

    _, sign_record = await executor.execute(
        registry.get("CryptoService", "DigestSign"),
        context,
        {"key_name": "demo-signing-key", "digest": "8f434346", "hash_algorithm": "SHA256"},
    )
    bundle = sign_record.artifacts[0].bundle()

    verify_result, _ = await executor.execute(
        registry.get("CryptoService", "DigestVerify"),
        context,
        {"bundle": json.dumps(bundle)},
    )
    assert verify_result.status is ResultStatus.OK
    assert verify_result.response["valid"] is True
    await clients.close()


@pytest.mark.asyncio
async def test_missing_token_reports_unauthenticated(crypto_endpoint) -> None:
    config = AppConfig(
        citius_endpoint=crypto_endpoint,
        citius_tls_enabled=False,
        session_cookie_secure=False,
    )

    async def token() -> str:
        return ""

    clients = CitiusClients(config, token)
    registry = build_registry(clients)
    executor = ActionExecutor(MemoryHistoryStore())
    context = ExecutionContext(session_id="h", subject="citius-producer")

    result, _ = await executor.execute(
        registry.get("CryptoService", "Sign"),
        context,
        {"key_name": "demo-signing-key", "message": "Hello"},
    )
    assert result.status is ResultStatus.UNAUTHENTICATED
    await clients.close()
