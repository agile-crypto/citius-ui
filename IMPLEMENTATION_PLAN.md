# Citius UI Implementation Plan

Status: in progress
Created: 2026-09-13
Target repository: `/home/navaneeth/GolandProjects/Citius/citius-ui`
Related server: `/home/navaneeth/GolandProjects/Citius/citius-server`
Reference UI: `/home/navaneeth/PycharmProjects/caas-ui`

## Implementation status

Last updated: 2026-09-17

### Completed so far

- [x] Define the one-application product direction: service-organized API Workbench, one authenticated user per browser session, inline producer-operation history, reusable examples, and multi-browser demonstrations.
- [x] Build and review a mock Gradio UI based on the reference application, including the revised visual theme, single-user session model, click-to-load examples, and inline crypto-response history.
- [x] Create `citius-api-python` as the generated Python protobuf/gRPC distribution and update the `citius-api` generation workflow to publish generated Python code there.
- [x] Create the `citius-server` branch `citius-ui-foundation` on top of `feat/module-topology-execution`.
- [x] Complete the planned `zitadel-grpc-auth` human-login foundation: human onboarding, explicit password reset, PKCE web-application reconciliation, read-only configuration verification, documentation, and live Zitadel coverage. This work is released as `v0.2.0`.
- [x] Extend the Citius Zitadel ACL schema for human users (`a66f858`).
- [x] Wire type-aware human identity provisioning through the canonical Citius setup tool (`65899ca`).
- [x] Declare the three Citius UI demo personas and their separated capabilities (`f8e9808`).
- [x] Add read-only Zitadel configuration verification and generate non-secret UI authentication configuration (`b45b5f5`).
- [x] Add interactive login and Citius authorization checks for the configured personas (`5c2dd9b`).
- [x] Cover the CISO, producer, and consumer method/resource authorization matrix, including `demo-restricted-*` deny precedence (`5c2dd9b`).
- [x] Implement, test, and publish the `zitadel-grpc-auth` follow-up that treats Zitadel's action-trigger `FailedPrecondition: No Changes` response as idempotent success (`0b81449`, released as `v0.2.1`).
- [x] Isolate every Citius `setup-auth` invocation from the root workspace with `GOWORK=off` and consume `zitadel-grpc-auth v0.2.1` (`327e458`).
- [x] Establish the `citius-ui` repository baseline with locked dependencies, project-local lint/test configuration, the reviewed single-user Gradio mock, examples, and per-session operation/producer-response history.
- [x] Implement the Python async gRPC client over `citius-api-python` in the standalone `citius-python-sdk` (Phase 1): `grpc.aio` channel factory with insecure/TLS/mTLS, validated CA material, per-call bearer metadata for unary and streaming RPCs, `CallableTokenProvider`, configurable deadlines and message-size limits, a normalized `CitiusError` hierarchy (`from_rpc_error`/`map_rpc_errors`), a lossless `OperationMetadata` wrapper, an API-version compatibility check, and the `Discovery`, `Crypto`, `KeyManagement`, and `CryptoPolicy` service clients covering the currently implemented RPCs. Verified by 45 unit tests with in-process fake gRPC servers.
- [x] Implement the transport-independent application layer core (Phase 2): the `RpcAction` model with availability and result-status enums, an `ActionRegistry`, typed `Artifact` bundles preserving the complete `OperationMetadata` with compatibility hand-off rules, the `OperationRecord` model, a session-isolated `MemoryHistoryStore` with bounded retention, request/response redaction, and a shared `ActionExecutor` that normalizes results, redacts snapshots, extracts artifacts, and records history. Verified by unit tests independent of Gradio and the SDK.

### Remaining work, in planned order

- [ ] Mount Gradio in FastAPI and add secure server-side sessions plus development authentication scaffolding (Phase 3).
- [ ] Build the initial service-organized Workbench for the currently implemented policy, key-management, and crypto RPCs, with unavailable RPCs shown honestly (Phase 4).
- [ ] Add inline producer-response history, copy/reuse actions, and Encrypt→Decrypt and Sign→Verify chaining across key rotation or transformation (Phase 5).
- [ ] Add the policy, access-control, requirements-driven key creation, and cryptographic-agility multi-browser runbooks (Phase 6).
- [ ] Wire production-style Zitadel Authorization Code with PKCE login, refresh, logout, token forwarding, and identity/claim display without exposing raw tokens (Phase 7).
- [ ] Expand the Workbench and demonstrations as discovery, provider, lifecycle, and migration RPCs become available (Phase 8).
- [ ] Add optional persistent history, deployment packaging, security hardening, observability, and end-to-end browser coverage (Phase 9).
- [ ] Reassess whether Gradio remains the right frontend after the first complete release; retain the transport and application layers if a dedicated frontend is adopted (Phase 10).

## 1. Objective

Build a maintainable Citius Console that serves two audiences without creating two independent applications:

1. **API Workbench** — lets users exercise the Citius API organized by its protobuf/gRPC services and RPC methods.
2. **Demo runbook** — demonstrates cryptographic policy, identity and access control, requirements-driven key creation, provider selection, and cryptographic agility across isolated browser sessions without introducing a second execution UI.

The Workbench and runbook must use the same Python gRPC client, RPC execution layer, response formatting, and operation history. Each browser has exactly one authenticated identity and its own history.

The UI is initially implemented with Gradio mounted in FastAPI. The design must keep the transport and application layers independent of Gradio so a future frontend can reuse the same backend concepts.

## 2. Product decisions

### 2.1 One application, one execution surface

Do not create separate “API tester” and “showcase” codebases. Keep one service-organized execution surface:

```text
Citius Console
├── Session identity
├── Multi-browser demo runbook
├── API Workbench
│   ├── Key Management Service
│   ├── Crypto Policy Service
│   ├── Crypto Service
│   ├── Algorithm Discovery Service
│   ├── Provider Service
│   ├── Key Establishment Service
│   └── Streaming Crypto Service
├── Previous producer responses (inside Crypto Service)
├── Session activity
└── Capability overview
```

The Workbench answers “what does this RPC do?” The runbook explains “why does this capability matter?” and tells the presenter which isolated browser to use. It does not maintain a second set of controls or switch identity inside one browser.

### 2.2 Python gRPC first

Use a server-side Python gRPC client. Do not make the REST gateway a prerequisite for the UI.

Reasons:

- The browser talks to the FastAPI/Gradio application, so it does not need native browser gRPC support.
- Python can use generated protobuf classes and `grpc.aio` directly.
- The UI can forward the current user’s bearer token as per-call gRPC metadata.
- This exercises Citius authentication and authorization exactly as a real client would.
- A REST gateway would not solve currently unimplemented server RPCs.

The REST gateway remains a separate server roadmap item for browser-native clients, OpenAPI consumers, and `curl` workflows.

### 2.3 Compiled API descriptors, not runtime reflection

Generate the Python protobuf/gRPC modules during development and package them with the application. Do not depend on gRPC reflection at runtime: Citius deliberately makes reflection optional, and unauthenticated reflection is unsuitable as a production dependency.

### 2.4 Honest capability reporting

RPCs present in protobuf but returning `UNIMPLEMENTED` remain visible in the Workbench with a clear status badge. Showcase scenarios must only be marked runnable when all required RPCs are implemented and available.

## 3. Findings from the existing systems

### 3.1 Patterns worth retaining from `caas-ui`

Retain or adapt these interaction ideas:

- Gradio `Blocks` composition.
- Feature-oriented component builders.
- Expandable examples and output panels.
- Clear/reset actions.
- Keeping prior signatures and ciphertexts available for follow-up operations.
- Simple hand-off from Sign to Verify and Encrypt to Decrypt.
- Friendly forms in front of a lower-level cryptographic API.

Before copying code verbatim, verify the reference project’s license and preserve any required attribution. Prefer adapting interaction patterns over copying large source sections.

### 3.2 Patterns that must be replaced

Do not carry forward:

- Hard-coded endpoints, mount names, credentials, or tokens.
- The Vault `hvac` transport layer.
- A process-global `username -> client` map.
- Gradio basic authentication disconnected from the identity used by the API.
- `ast.literal_eval` or free-form Python syntax for structured request fields.
- A single large UI module containing views, auth, transport, and state.
- Separate ad hoc DataFrames for each output type.
- Printing tokens or sensitive cryptographic values to logs.

### 3.3 Current Citius implementation baseline

The initial Workbench can call these implemented RPCs:

| Service | Implemented RPCs |
|---|---|
| Crypto Policy | CreateCryptoPolicy, ReadCryptoPolicy, UpdateCryptoPolicy |
| Key Management | CreateKey, ReadKey, TransformKey |
| Crypto | Encrypt, Decrypt, Sign, Verify, DigestSign, DigestVerify |

The following important groups are currently protobuf contracts backed by unimplemented handlers:

- Algorithm discovery RPCs.
- Provider catalog, instance, and matching RPCs.
- Policy delete, list, evaluate, and batch evaluate.
- Key list, delete, rotate, policy update, migrate, validation, import, and export.
- MAC, digest, XOF, and random operations.
- Key establishment and streaming operations.

The UI plan therefore includes explicit server dependencies rather than masking missing behavior in the UI.

## 4. Target architecture

```text
Browser
  │ HTTPS + secure session cookie
  ▼
FastAPI host
  ├── OIDC login/callback/logout
  ├── server-side session and token store
  ├── Gradio mount and auth_dependency
  └── health/readiness endpoints
          │
          ▼
UI application layer
  ├── RPC action registry
  ├── request validation/building
  ├── response and error normalization
  ├── artifact extraction
  ├── history recorder
  └── demo-runbook bindings
          │
          ▼
Python gRPC client
  ├── generated protobuf modules
  ├── TLS channel pool
  ├── bearer metadata per call
  ├── deadlines
  └── correlation IDs
          │ HTTP/2 + TLS
          ▼
citius-server
```

Important boundary: UI code may construct protobuf requests and render results, but it must not reproduce Citius policy evaluation, template selection, provider matching, or authorization decisions.

## 5. Proposed repository layout

```text
citius-ui/
├── README.md
├── IMPLEMENTATION_PLAN.md
├── pyproject.toml
├── uv.lock
├── .env.example
├── .gitignore
├── Dockerfile
├── compose.yaml
├── scripts/
│   ├── generate_proto.sh
│   ├── check_proto_version.sh
│   └── provision_demo_users.sh
├── demo/
│   └── users.yaml
├── src/citius_ui/
│   ├── main.py
│   ├── config.py
│   ├── logging.py
│   ├── auth/
│   │   ├── oidc.py
│   │   ├── sessions.py
│   │   ├── demo_personas.py
│   │   └── redaction.py
│   ├── generated/
│   │   └── ... generated *_pb2.py and *_pb2_grpc.py
│   ├── grpc_client/
│   │   ├── channel.py
│   │   ├── client.py
│   │   ├── errors.py
│   │   ├── serialization.py
│   │   └── services/
│   ├── actions/
│   │   ├── model.py
│   │   ├── registry.py
│   │   └── artifacts.py
│   ├── history/
│   │   ├── model.py
│   │   ├── memory_store.py
│   │   ├── sqlite_store.py
│   │   └── service.py
│   ├── workbench/
│   │   ├── common.py
│   │   ├── key_management.py
│   │   ├── crypto_policy.py
│   │   ├── crypto.py
│   │   ├── discovery.py
│   │   ├── providers.py
│   │   ├── key_establishment.py
│   │   └── streaming.py
│   ├── showcases/
│   │   ├── model.py
│   │   ├── runner.py
│   │   ├── policy_enforcement.py
│   │   ├── access_control.py
│   │   ├── key_requirements.py
│   │   ├── agility.py
│   │   └── provider_migration.py
│   └── ui/
│       ├── app.py
│       ├── navigation.py
│       ├── theme.py
│       └── components/
└── tests/
    ├── unit/
    ├── contract/
    ├── integration/
    └── e2e/
```

The exact package manager should be chosen during repository bootstrap. Prefer `uv` with a locked dependency set unless organizational standards require Poetry.

## 6. Python API generation and compatibility

### 6.1 Generation

Generate Python protobuf messages and gRPC stubs from the same canonical proto revision used by citius-server. Add a deterministic generation command and CI drift check.

Required runtime libraries:

- `grpcio`
- `protobuf`
- `grpcio-status` if rich status details are used
- Gradio
- FastAPI and Uvicorn
- Authlib for OIDC

Do not hand-maintain request/response models that duplicate protobuf definitions.

### 6.2 API ownership decision

Resolve the canonical source of API protos before the first generated-code commit. The preferred long-term arrangement is a versioned Citius API distribution that produces both Go and Python SDK artifacts. Until that exists, pin the exact proto source revision used to generate the checked-in Python modules and record it in a manifest.

### 6.3 Client behavior

The client layer must provide:

- Async stubs using `grpc.aio`.
- TLS root-CA configuration and explicit insecure local-development mode.
- Bearer token supplied per call, never fixed globally on a shared multi-user channel.
- Configurable deadlines and message-size limits.
- Connection/readiness checks.
- Normalized errors preserving gRPC code, message, and safe details.
- Protobuf-to-dictionary conversion preserving field names and enum names.
- Byte rendering controls: UTF-8 where valid, Base64, and hex.
- Optional request correlation ID metadata.

## 7. Authentication and session design

### 7.1 Production-style interactive login

Mount Gradio in FastAPI. Implement Zitadel Authorization Code with PKCE and use Gradio’s `auth_dependency` to require a valid FastAPI session.

The server-side session contains a reference to:

- Subject/user ID and display name.
- Access token and expiry.
- Refresh token when configured.
- Granted identity information safe to display.
- Selected Citius endpoint.
- History/session ID.

The access token is forwarded unchanged to citius-server so its method permissions and key/policy glob restrictions remain authoritative.

### 7.2 Demo persona mode

Support an explicitly configured development-only sign-in for seeded identities. One browser session holds exactly one identity; changing identity requires logout and replacement of the session. Concurrent personas use different browsers, isolated profiles, or container tabs. Credentials remain server-side. The browser sees persona metadata, never service-account secrets or full bearer tokens.

### 7.3 Security requirements

- Secure, HTTP-only, SameSite cookies.
- CSRF-safe login state and logout.
- Token refresh and expiry handling.
- No token logging.
- No process-global state keyed only by username.
- Separate sessions for concurrent logins by the same user.
- TLS required when sending bearer credentials, except an explicit local-only development mode.

### 7.4 Three interactive demonstration users

Provision three real Zitadel human users that mirror the useful separation in the reference UI while using Citius's native permissions and resource claims. These are UI personas, not replacements for the existing machine users used by integration tests.

| Persona | Purpose | Granted capability groups | Intentionally excluded |
|---|---|---|---|
| `citius-ciso` | Governance and key lifecycle administrator | Policy read/write; key create/read/rotate/update-policy; discovery read; provider read; optionally provider write | Encrypt, decrypt, sign, verify |
| `citius-producer` | Key creator, signer, and encrypter | Policy read; key create/read; discovery read; provider read; sign; encrypt | Decrypt, verify, policy write, transform/migrate, provider write |
| `citius-consumer` | Verifier and decrypter | Policy read; key read; discovery read; verify; decrypt | Key creation, sign, encrypt, policy write, lifecycle operations |

Use these exact Citius permission keys unless the canonical permission catalog changes:

```text
citius:keys:create
citius:keys:rotate
citius:keys:update-policy
citius:keys:read
citius:crypto:encrypt
citius:crypto:decrypt
citius:crypto:sign
citius:crypto:verify
citius:policy:read
citius:policy:write
citius:discovery:read
citius:provider:read
citius:provider:write
```

Do not grant `permissions: ["*"]` to any of the three demonstration users. The purpose is to make separation of duties visible. Keep the existing `svc-admin`, `svc-tester`, `svc-readonly`, and `svc-noperm` machine users for automated integration and negative-control tests.

Provider write access for `citius-ciso` is configurable. Enable it in the full provider-administration showcase; omit it in deployments where provider registration is an operator-only responsibility.

### 7.5 Resource scope for the personas

All three personas require access to a shared demonstration namespace so a policy created by the CISO, a key created by the producer, and an artifact verified or decrypted by the consumer can participate in one workflow:

```yaml
key_access:
  allow: ["demo-*"]

policy_access:
  allow: ["demo-*"]
```

Add explicit denied names to producer and consumer accounts to demonstrate deny precedence independently of RPC permissions:

```yaml
key_access:
  allow: ["demo-*"]
  deny: ["demo-restricted-*"]

policy_access:
  allow: ["demo-*"]
  deny: ["demo-restricted-*"]
```

The CISO may retain access to every `demo-*` resource but should not receive access to production-style names. Resource patterns are stored as Zitadel metadata and projected into the access token by the existing Citius claim action. Users must not have permission to modify their own authorization metadata.

### 7.6 Declarative user specification

Add `demo/users.yaml` to this repository as the non-secret declaration of the three identities. Extend the canonical Citius Zitadel ACL/provisioning model to support both machine and human entries instead of building a second permission implementation in the UI.

Proposed shape:

```yaml
version: 1

users:
  - username: citius-ciso
    user_type: human
    display_name: Citius CISO
    email: citius-ciso@citius.local
    password_env: CITIUS_DEMO_CISO_PASSWORD
    password_change_required: false
    permissions:
      - citius:policy:read
      - citius:policy:write
      - citius:keys:create
      - citius:keys:read
      - citius:keys:rotate
      - citius:keys:update-policy
      - citius:discovery:read
      - citius:provider:read
    key_access:
      allow: ["demo-*"]
    policy_access:
      allow: ["demo-*"]

  - username: citius-producer
    user_type: human
    display_name: Citius Producer
    email: citius-producer@citius.local
    password_env: CITIUS_DEMO_PRODUCER_PASSWORD
    password_change_required: false
    permissions:
      - citius:policy:read
      - citius:keys:create
      - citius:keys:read
      - citius:discovery:read
      - citius:provider:read
      - citius:crypto:sign
      - citius:crypto:encrypt
    key_access:
      allow: ["demo-*"]
      deny: ["demo-restricted-*"]
    policy_access:
      allow: ["demo-*"]
      deny: ["demo-restricted-*"]

  - username: citius-consumer
    user_type: human
    display_name: Citius Consumer
    email: citius-consumer@citius.local
    password_env: CITIUS_DEMO_CONSUMER_PASSWORD
    password_change_required: false
    permissions:
      - citius:policy:read
      - citius:keys:read
      - citius:discovery:read
      - citius:crypto:verify
      - citius:crypto:decrypt
    key_access:
      allow: ["demo-*"]
      deny: ["demo-restricted-*"]
    policy_access:
      allow: ["demo-*"]
      deny: ["demo-restricted-*"]
```

The committed file contains no passwords. Email domain, password-change policy, and optional provider-write grant must be configurable for non-local deployments.

### 7.7 Provisioning script ownership and behavior

Add `scripts/provision_demo_users.sh` as a thin, operator-facing entry point. Identity provisioning remains owned by the canonical Zitadel bootstrap rather than the Gradio process.

The wrapper must:

1. Resolve `CITIUS_SERVER_DIR`, defaulting to the sibling `../citius-server` only when that directory validates as the expected repository.
2. Confirm the Zitadel bootstrap project and claim action already exist.
3. Validate `demo/users.yaml` strictly before making network calls.
4. Check required password environment variables or invoke secure password generation when explicitly requested.
5. Invoke the canonical Citius Zitadel provisioner with the UI ACL.
6. Verify user type, project-role grants, and key/policy metadata after reconciliation.
7. Print a capability summary without printing passwords, client secrets, tokens, or PATs.
8. Return non-zero on partial provisioning or verification failure.

The canonical provisioner must be extended to reconcile human users in addition to its current machine-user support. Preferred implementation order:

1. Extend the reusable `zitadel-grpc-auth/admin` API with a human-user onboarding input and idempotent reconciliation if that module remains the canonical shared abstraction.
2. Extend `citius-server/bootstrap/zitadel/setup-auth` ACL parsing with `user_type`, human profile fields, and `password_env` validation.
3. Reuse the existing strict permission validation, project authorization reconciliation, metadata reconciliation, and claim action.
4. Preserve the current machine-user behavior and generated client-secret output unchanged.
5. Add an explicit `human-users` or type-aware `users` command; do not silently reinterpret existing ACL entries.

If changing the shared auth module is not practical, implement a small human-user adapter in `setup-auth` using the same Zitadel SDK client and reconciliation functions. Do not duplicate the Citius permission catalog in Python or shell.

### 7.8 Password and lifecycle rules

- Passwords come from named environment variables or are generated with a cryptographically secure generator.
- No deterministic or example password is committed.
- Generated passwords are displayed once or written only to a gitignored local file with mode `0600`.
- Normal logs show neither passwords nor tokens.
- Re-running provisioning reconciles roles and metadata but does not rotate passwords unless `--rotate-passwords` is explicitly supplied.
- `--dry-run` performs parsing, permission validation, environment validation, and a read-only reconciliation preview.
- User deletion is never part of the default reconcile path.
- Destructive removal requires a separate explicit command and confirmation/force flag.
- `password_change_required: false` is permitted only for a local demonstration profile; shared or production-like environments default it to true.
- The UI never collects these passwords directly. Users authenticate on the Zitadel-hosted login page through Authorization Code with PKCE.

### 7.9 Provisioning verification and negative controls

Automated verification must prove:

1. All three human users exist and are active.
2. Each has exactly the intended Citius project roles after reconciliation.
3. Allowed and denied key/policy patterns are projected into a login token.
4. The CISO can manage a `demo-*` policy/key but cannot perform a deliberately excluded crypto operation.
5. The producer can sign/encrypt but receives `PERMISSION_DENIED` for verify/decrypt.
6. The consumer can verify/decrypt but receives `PERMISSION_DENIED` for sign/encrypt.
7. Producer and consumer are denied access to `demo-restricted-*` even for an otherwise granted method.
8. An invalid password cannot create a UI session.
9. A token from one user is never retained after logout or substituted into another browser session.

Because human access tokens require an interactive OIDC flow, split tests appropriately:

- Provisioner unit/integration tests verify Zitadel user, grant, and metadata state.
- Browser end-to-end tests perform actual hosted login and Citius calls.
- Existing machine identities continue to provide fast non-browser auth integration coverage.

## 8. Shared RPC action model

Every callable RPC is represented by a reusable action definition:

```python
RpcAction(
    service="caas.crypto.v1.KeyManagementService",
    method="CreateKey",
    request_type=CreateKeyRequest,
    invoke=client.key_management.create_key,
    form_factory=create_key_form,
    artifact_extractor=extract_key_artifacts,
)
```

An action owns or references:

- Request construction and client-side structural validation.
- RPC invocation.
- Response normalization.
- Safe request/response rendering.
- Artifact extraction.
- History recording.
- Workbench deep-link information.

Workbench pages render actions directly. Showcase scenarios compose actions. History replays actions. No RPC callback should bypass this layer.

## 9. API Workbench design

### 9.1 Service organization

Mirror protobuf service names and method groups. Each method view provides:

- Friendly typed form.
- Advanced protobuf-JSON editor.
- Synchronized form/JSON values where practical.
- Example and preset requests.
- Generated request preview.
- Execute and clear actions.
- Response, metadata, latency, and gRPC status.
- Copy as Python and copy as `grpcurl`.
- Replay, duplicate, and add-output-to-input actions.

Use compiled descriptors to supply field descriptions and advanced JSON templates. Create curated forms for important RPCs rather than attempting to generate the complete user experience solely from descriptors.

### 9.2 Availability states

Each RPC displays one of:

- Available.
- Unimplemented by the connected server.
- Unavailable because a server dependency is missing.
- Forbidden for the current identity.
- Unknown until probed.

Permission-sensitive RPCs should not be hidden. Showing a deliberate `PERMISSION_DENIED` result is part of the API exploration value.

### 9.3 Error presentation

Distinguish clearly among:

- `UNAUTHENTICATED`: token absent, invalid, or expired.
- `PERMISSION_DENIED`: identity lacks method or resource permission.
- Cryptographic-policy rejection.
- Invalid request or template/provider mismatch.
- `NOT_FOUND`.
- `UNIMPLEMENTED`.
- Connectivity/TLS/deadline failure.

## 10. Unified operation history

### 10.1 Data model

Use one history model for all services and both UI modes:

```text
OperationRecord
├── id
├── timestamp
├── session/user reference
├── endpoint and API version
├── service and method
├── request snapshot (redacted)
├── response snapshot (redacted)
├── gRPC code and safe details
├── duration
├── correlation ID
├── extracted artifacts
├── scenario run/step reference
└── replayability metadata
```

### 10.2 Artifact types

Initial typed artifacts:

- Key reference and key metadata.
- Policy reference/document.
- Template reference.
- Provider/provider-instance reference.
- Plaintext reference.
- Ciphertext plus operation metadata.
- Signature plus operation metadata.
- Digest.
- Public key.

For long-lived cryptographic outputs, the artifact value and the complete
`OperationMetadata` are one logical bundle. The UI must retain at least
`key_version`, `provider_output` (including nonce/IV and encoding), and
`api_version`; copying or replaying only the signature/ciphertext is not a
valid compatibility workflow.

Artifacts enable context-aware transitions:

- Encrypt output -> Decrypt input.
- Sign output -> Verify input.
- Key result -> ReadKey or TransformKey.
- Policy result -> CreateKey.
- Template result -> CreateKey.
- Provider match -> CreateKey or MigrateKey.

### 10.3 Storage policy

Default to session-only, server-side memory storage. Add optional SQLite persistence later.

Never persist or display in history:

- Access or refresh tokens.
- Provider secrets.
- Client credentials.
- Private key material.
- Raw imported/exported key material.

Payload history defaults to digest, size, type, and a truncated preview. Full payload persistence requires an explicit development setting or per-operation user action. Persistent records are scoped to the authenticated subject and governed by configurable retention.

### 10.4 History UI

Provide:

- Timeline and table views.
- Filters by service, method, key, policy, status, and scenario.
- Request/response detail drawer.
- Replay and duplicate/edit.
- Compare two operations.
- Send artifact to a compatible RPC.
- Append successful Sign, DigestSign, and Encrypt responses directly beneath the
  Crypto Service controls, following the reference UI. Each row shows the key name
  and a copyable complete value-plus-metadata bundle suitable for Verify/Decrypt.
- Export a sanitized scenario run as JSON.
- Clear session history.

## 11. Multi-browser demo runbook

The runbook is declarative documentation over the same registered RPC actions; it is not a second execution UI. Each step names the required browser identity, service/RPC, example input, expected result category, explanatory text, and any safe response bundle to copy to another browser. It may populate the relevant Workbench request, but it never switches the authenticated identity.

### 11.1 Policy enforcement

1. Create or select a restrictive crypto policy.
2. Create a governed key.
3. Perform an allowed operation.
4. Attempt a forbidden algorithm/operation.
5. Compare the successful call and policy rejection.

### 11.2 Identity and access control

1. Log in as the CISO and create `demo-signing-policy`.
2. Log out, then log in as the producer and create `demo-signing-key` under that policy.
3. Sign a message and retain the signature as a safe scenario artifact.
4. Attempt Verify as the producer and show the method-level `PERMISSION_DENIED` result.
5. Log out, then log in as the consumer and verify the retained signature.
6. Attempt Sign as the consumer and show the method-level denial.
7. Attempt an otherwise permitted operation on `demo-restricted-key` and show resource-level deny precedence.
8. Explain method-level permission gates versus key/policy resource patterns.

Identity transitions must replace and invalidate the active UI auth session. A scenario run may retain explicitly safe artifacts such as a key name, message, signature, ciphertext, or operation metadata, but it must never retain or transfer the previous identity's access/refresh token, password, or provider secrets. Cross-user scenario artifacts are grouped under an opaque scenario-run ID and remain separate from each user's private persistent history.

### 11.3 Requirements-driven key creation

1. Select cryptographic intent/scope.
2. Add algorithm requirements such as strength, FIPS approval, or quantum safety.
3. Add implementation requirements such as FIPS level, constant time, memory safety, or hardware acceleration.
4. Preview matching templates/providers when discovery RPCs are available.
5. Create the key.
6. Present a “key passport” explaining selected template, provider, policy, security guarantees, and implementation properties.

### 11.4 Cryptographic agility

1. Read the current key metadata.
2. Select a new scope/template.
3. Choose whether to retain key bytes.
4. Transform the key.
5. Compare before/after template, version, guarantees, and metadata.
6. Demonstrate behavior of data produced before transformation when supported.
7. Verify a pre-transform signature and decrypt pre-transform ciphertext by
   replaying the recorded `OperationMetadata.key_version`; also show the
   negative control where omitting that metadata selects the current version.

### 11.5 Provider selection and migration

Keep provider migration separate from algorithm transformation:

1. Discover providers and instances.
2. Match implementation requirements.
3. Validate migration options.
4. Select an explicit migration strategy.
5. Migrate or rekey.
6. Compare provider and implementation properties before/after.

This scenario remains disabled until the corresponding ProviderService and KeyManagementService RPCs are implemented.

## 12. Server dependencies and coordinated backlog

The UI repository should track these as external dependencies with links to citius-server issues. Recommended server order:

### Server priority A — dynamic Workbench baseline

1. `ListTemplates`, `GetTemplate`, `ListScopes`.
2. `ListProviders`, `GetProvider`, `MatchProviders`.
3. `ListProviderInstances`, `GetProviderInstance`.
4. `ListKeys`.
5. `ListCryptoPolicies`.
6. `EvaluatePolicy` and `BatchEvaluatePolicy`.
7. `RotateKey`.

### Server priority B — lifecycle and administration

1. Policy delete.
2. Key delete and policy update.
3. Provider instance registration/update/delete.
4. `ValidateKeyOperation` and `MigrateKey`.
5. Import/export with strict UI redaction.

### Server priority C — expanded crypto surface

1. MAC, digest, XOF, and random.
2. Key establishment.
3. Streaming operations and UI session-state recovery.

The UI must not simulate these server decisions merely to make a scenario appear complete.

## 13. Implementation phases and commit plan

Implement in small, reviewable commits. Each commit must leave the repository runnable or clearly limited to scaffolding, include proportional tests, and update documentation when behavior changes.

### 13.1 Repository ownership and dependency order

The implementation spans five repositories. Keep responsibilities explicit:

| Repository | Responsibility | Must not own |
|---|---|---|
| `zitadel-grpc-auth` | Reusable Zitadel project/app bootstrap, human-user onboarding, password initialization, role grants, and authorization metadata reconciliation | Citius-specific UI or RPC clients |
| `citius-server` | Canonical Citius permission catalog, Citius ACL declaration, claim-action configuration, and wrapper that provisions/verifies the three demo users | Browser sessions or user passwords in source control |
| `citius-api-python` (new) | Deterministically generated Python protobuf and gRPC modules from the canonical Citius API release | Client ergonomics, authentication sessions, or UI behavior |
| `citius-python-sdk` (new) | Ergonomic Citius service clients, configuration, TLS, deadlines, token injection, request helpers, response helpers, and normalized errors | Generated API ownership, interactive login, cookie sessions, or Zitadel administration |
| `citius-ui` | FastAPI/Gradio application, OIDC session, Workbench actions, examples, response history, and demo runbook | Cryptographic policy evaluation or long-term credential storage |

The effective dependency graph is:

```text
Citius API proto revision ─► citius-api-python ─► citius-python-sdk ─┐
                                                                   │
zitadel-grpc-auth human users + Web app ─► citius-server bootstrap ├─► citius-ui wiring
                                                                   │
Zitadel hosted login + PKCE configuration ─────────────────────────┘
```

Do not begin with a username/password form inside Gradio. First provision a Zitadel Web/OIDC application and human users, then redirect the browser to Zitadel's hosted login. The browser uses Authorization Code with PKCE; the resulting access token is held in a server-side UI session and supplied to the Python SDK. The SDK neither sees the password nor performs a password grant.

Two foundation tracks can proceed in parallel after their contracts are fixed:

1. **Identity foundation:** extend `zitadel-grpc-auth`, then extend the Citius ACL/bootstrap wrapper.
2. **Client foundation:** create and validate the standalone `citius-python-sdk` from the canonical API protos.

UI authentication starts after the Zitadel Web app and one human test user can be provisioned. Full RPC wiring starts after the Python SDK can make one authenticated unary call.

### 13.2 Identity foundation deliverables

Extend `zitadel-grpc-auth/admin` with a separate human-user onboarding contract rather than overloading the current machine-user secret flow. The contract includes username, given/family/display name, email, initial password, password-change requirement, permissions, key access, and policy access.

Required behavior:

1. Create a Zitadel human user through `UserServiceV2.CreateUser` with the human profile, verified/local-demo email policy, and initial password.
2. Reuse the existing authorization and metadata reconcilers so human and machine users receive identical project roles and Citius ACL claims.
3. On re-run, reconcile profile, roles, and metadata without changing the password.
4. Change a password only through an explicit rotate/reset operation.
5. Detect and reject a username that exists with the wrong user type.
6. Reconcile a Zitadel Web/OIDC application configured with Authorization Code, PKCE, exact redirect URIs, and exact post-logout URIs.
7. Return identifiers and non-secret status only; never return or log the initial password.

Extend the Citius ACL schema with `user_type`, human profile fields, `password_env`, and `password_change_required`. The committed declaration contains the three demo users and no password values. A `citius-ui/scripts/provision_demo_users.sh` wrapper invokes the canonical `citius-server/bootstrap/zitadel/setup-auth` implementation; it does not duplicate Zitadel API calls.

Identity acceptance gate:

- An idempotent dry-run validates the ACL without network mutation.
- Apply creates/reconciles CISO, producer, and consumer as human users.
- Passwords are read only from named environment variables or secure generated output.
- Interactive login succeeds for all three users.
- Tokens contain the expected audience, permission claim, allowed patterns, and deny patterns.
- Invalid passwords fail, and producer/consumer negative authorization controls return `PERMISSION_DENIED`.

### 13.3 Python SDK foundation deliverables

Create two standalone repositories, matching the current Go distribution boundary:

1. `/home/navaneeth/GolandProjects/Citius/citius-api-python` is generated-only and publishes versioned Python protobuf/gRPC bindings from a pinned revision of `/home/navaneeth/GolandProjects/Citius/api/proto`.
2. `/home/navaneeth/GolandProjects/Citius/citius-python-sdk` depends on an exact compatible `citius-api-python` release and provides the ergonomic client layer. It does not regenerate or vendor the API bindings.

Mirror the useful Go SDK boundaries in Python:

```text
src/citius_sdk/
├── config.py              # endpoint, per-service overrides, TLS, deadlines
├── auth.py                # TokenProvider protocol and static/callable providers
├── channel.py             # grpc.aio channel and credential construction
├── errors.py              # normalized gRPC failures
├── metadata.py            # OperationMetadata helpers; no information loss
└── services/
    ├── crypto.py
    ├── key_management.py
    ├── crypto_policy.py
    ├── discovery.py
    ├── provider.py
    ├── key_establishment.py
    └── streaming_crypto.py
```

Use `grpc.aio` as the primary transport because the UI backend is asynchronous. Provide a minimal `TokenProvider` protocol that is called for each RPC and supports refreshed user access tokens. The UI supplies that provider from its authenticated session. The SDK must support insecure local development, server TLS, mTLS, per-RPC deadlines, message-size limits, unary and streaming token metadata, generated-code drift checks, and protobuf-to-dictionary rendering that preserves field and enum names.

SDK acceptance gate:

- `citius-api-python` has deterministic generation and a CI drift check tied to a recorded API commit/tag.
- The SDK pins a compatible generated API version and tests that dependency boundary.
- Unit tests use in-process fake gRPC servers for every service client.
- TLS, mTLS, missing token, refreshed token, timeout, and error-mapping tests pass.
- A contract test calls one implemented Citius RPC with auth disabled.
- An integration test calls one implemented RPC with a Zitadel access token and distinguishes `UNAUTHENTICATED` from `PERMISSION_DENIED`.
- Signature/ciphertext response models preserve complete `OperationMetadata`, especially `key_version` and provider output.

### 13.4 UI authentication and wiring deliverables

Replace mock sign-in with FastAPI-managed OIDC routes and mount Gradio behind an authentication dependency:

1. `/login` starts Authorization Code with PKCE and redirects to Zitadel.
2. `/auth/callback` validates state, nonce, issuer, and token response, then creates a server-side session.
3. The browser receives only a secure, HTTP-only, SameSite session cookie.
4. Access and refresh tokens remain in the server-side session store and are redacted from logs/history.
5. `/logout` clears local state and performs Zitadel end-session logout when configured.
6. Each browser session has exactly one subject; switching users requires logout.
7. The session-backed token provider is passed to `citius-python-sdk` for each RPC.

Then replace the mock executor one service at a time. Start with Read/CreateCryptoPolicy, Read/CreateKey, Sign/Verify, and Encrypt/Decrypt. Preserve the approved UI structure: service accordions, clickable examples, current response, append-only producer response history with key name and complete metadata bundle, and per-browser session activity.

End-to-end acceptance gate:

- Three isolated browser profiles can log in concurrently as CISO, producer, and consumer.
- Their cookies, tokens, and histories remain isolated.
- They see the same server-side policies and keys.
- CISO creates policy; producer creates a key and signs/encrypts; consumer verifies/decrypts a copied bundle.
- A pre-rotation/pre-transformation bundle still verifies/decrypts through its recorded key version.
- Method-level and resource-level denials are visibly distinct from login failure, validation failure, and unimplemented RPCs.

### Phase 0 — repository foundation

1. Add README, license decision, Python version, package manager, formatting, linting, and test configuration.
2. Add application configuration with `.env.example`; no real secrets.
3. Add CI for format, lint, type-check, unit tests, and secret scanning.
4. Document local relationship to citius-server and Zitadel bootstrap.

Exit criteria: clean installation and a tested configuration loader.

### Phase 1 — protobuf generation and gRPC transport

1. Establish canonical proto source/version manifest.
2. Add deterministic Python generation script.
3. Add generated-code drift check.
4. Implement TLS/insecure-dev channel factory.
5. Implement bearer metadata, deadlines, health/readiness probe, and error normalization.
6. Add unit tests with fake channels and a contract test against a test server.

Exit criteria: a Python test can call one implemented Citius RPC and correctly distinguish success, unauthenticated, and permission denied.

### Phase 2 — action registry and history core

1. Define `RpcAction`, normalized result, artifact, and operation-record models.
2. Implement the shared executor.
3. Implement redaction before recording or logging.
4. Implement session memory history.
5. Implement artifact compatibility and hand-off rules.
6. Test successful, failed, replayed, and redacted operations.

Exit criteria: all calls pass through one executor and create safe history records.

### Phase 3 — FastAPI, sessions, and development authentication

1. Add FastAPI host and mount a minimal Gradio app.
2. Add secure server-side session abstraction.
3. Add token-paste mode for local development.
4. Add optional server-side demo personas.
5. Add endpoint/TLS status and identity panel.
6. Verify concurrent sessions cannot see each other’s token or history.

Exit criteria: two browser sessions can call Citius independently with different permissions.

### Phase 4 — initial API Workbench

Implement curated pages for currently working RPCs:

1. Crypto Policy: create, read, update.
2. Key Management: create, read, transform.
3. Crypto: encrypt, decrypt, sign, verify, digest-sign, digest-verify.
4. Register remaining protobuf methods as visibly unavailable/unimplemented.
5. Add protobuf JSON, response inspector, examples, copy, and replay.

Exit criteria: every currently implemented RPC is callable from the service-organized UI and recorded in history.

### Phase 5 — history UI and operation chaining

1. Add session activity table/timeline and filters.
2. Add request/response inspector.
3. Add Encrypt -> Decrypt and Sign -> Verify hand-offs.
4. Add append-only producer response history inside Crypto Service with key names,
   versions, complete metadata bundles, and copyable consumer inputs.
5. Add key/policy artifact navigation.
6. Add compare and sanitized export.
7. Add retention and payload-display controls.

Exit criteria: the existing UI’s signature/ciphertext history capability is preserved and generalized across all services.

### Phase 6 — first multi-browser runbooks

1. Policy enforcement scenario using available RPCs.
2. Identity/access-control negative-path scenario.
3. Requirements-driven key creation scenario.
4. Transform/agility scenario.
5. Add step-to-Workbench deep links and optional run IDs without merging user histories.

Exit criteria: runbooks use the same actions as the Workbench; calls appear only in the current user's session activity and producer responses are transferred explicitly as safe copyable bundles.

### Phase 7 — Zitadel interactive login

1. Register/configure a Zitadel Web application.
2. Extend the canonical Zitadel provisioner to support idempotent human-user reconciliation without changing existing machine-user behavior.
3. Add and strictly validate `demo/users.yaml` for CISO, producer, and consumer.
4. Add `scripts/provision_demo_users.sh` with dry-run, reconcile, verify, and explicit password-rotation behavior.
5. Implement Authorization Code with PKCE.
6. Implement callback, refresh, expiry, session replacement, and federated logout.
7. Verify the token contains the Citius audience, permissions, and resource-pattern claims expected by citius-server.
8. Add end-to-end tests for the three personas, method denials, and resource-pattern denials.

Exit criteria: one idempotent command provisions and verifies the three human personas; hosted login produces a token that is forwarded to Citius and enforces the logged-in user's exact method and resource permissions.

### Phase 8 — discovery/provider expansion

After the corresponding server RPCs land:

1. Populate scope, template, provider, and instance controls dynamically.
2. Add provider requirement builder.
3. Show provider match scores and resolved implementation properties.
4. Add provider administration Workbench pages.
5. Add provider migration showcase after validation/migration RPCs land.

Exit criteria: no hard-coded template/provider catalog is required for normal operation.

### Phase 9 — persistence and deployment

1. Add optional SQLite history store and migrations.
2. Add user scoping, retention, and cleanup jobs.
3. Add Dockerfile and local Compose integration.
4. Add health/readiness probes and structured redacted logging.
5. Add browser end-to-end tests.
6. Add production deployment and reverse-proxy documentation.

Exit criteria: repeatable containerized deployment with secure sessions and tested cleanup.

### Phase 10 — frontend reassessment

Evaluate Gradio after representative internal and external users exercise the console. Consider a custom web frontend only if limitations appear in navigation, accessibility, state management, URL/deep-link handling, or high-volume history. Preserve the Python gRPC/action/history backend contracts if the frontend changes.

## 14. Testing strategy

### Unit tests

- Configuration validation.
- Protobuf serialization and byte rendering.
- Error normalization.
- Redaction.
- Artifact extraction and compatibility.
- History isolation and retention.
- Scenario input/output binding.

### Contract tests

- Generated Python request/response compatibility with the connected server version.
- Every registered action points to an existing service/method descriptor.
- Availability matrix agrees with server responses.

### Integration tests

- Insecure local channel when auth is disabled.
- TLS channel with bearer token when auth is enabled.
- Success with admin/tester identity.
- `UNAUTHENTICATED` with missing/expired token.
- `PERMISSION_DENIED` for missing method permission.
- `PERMISSION_DENIED` for forbidden key/policy patterns.
- Policy denial remains distinguishable from IAM denial.
- Idempotent human-user provisioning and grant/metadata reconciliation.
- Password rotation occurs only when explicitly requested.

### Browser end-to-end tests

- Login/logout and session expiry.
- Workbench request execution.
- History update and filtering.
- Encrypt -> Decrypt and Sign -> Verify hand-offs.
- Runbook step progression and Workbench deep links without identity switching.
- Isolation between concurrent browser sessions.
- Hosted login and logout for CISO, producer, and consumer.
- Cross-persona scenario continuation without credential or token carry-over.

### Negative controls

For every new authorization, redaction, or sensitive-history test, prove the test fails when the protection is deliberately disabled. Do not weaken existing assertions merely to accommodate implementation behavior.

## 15. Observability and diagnostics

- Structured logs with correlation ID, service, method, gRPC code, and duration.
- Never log tokens, secrets, key material, or unredacted request bodies.
- Connection status includes endpoint, TLS mode, API version/manifest, and last successful probe.
- History records client-visible failures even when an RPC never reaches the server.
- Optional OpenTelemetry hooks may be added after core flows stabilize.

## 16. Definition of done for the first release

The first release is complete when:

1. One application exposes Workbench and Showcase modes.
2. Workbench navigation mirrors all protobuf gRPC services.
3. All currently implemented RPCs are callable with typed forms and protobuf JSON inspection.
4. Every invocation passes through the shared executor and appears in per-user history.
5. Encrypt/Decrypt and Sign/Verify outputs can be chained from history.
6. A signature or ciphertext produced under an older key version remains
    usable after rotation/transformation when replayed with its original
    operation metadata, and fails the negative-control test when the version
    metadata is omitted or changed.
7. At least four guided scenarios run through the same action definitions.
8. Bearer tokens are forwarded per user and real Citius authorization denials are visible.
9. Tokens, secrets, and key material are redacted from logs/history.
10. Concurrent sessions are isolated.
11. Unit, contract, integration, and core browser tests pass in CI.
12. Unimplemented server RPCs are identified honestly and never emulated in the UI.
13. Local setup against citius-server and Zitadel is documented and reproducible.
14. The provisioning script idempotently creates/verifies the three human UI personas without committed credentials.
15. The identity showcase demonstrates CISO governance, producer sign/encrypt, consumer verify/decrypt, method denial, and resource-pattern denial.

## 17. Decisions to close during Phase 0

These do not block creation of the repository but must be resolved before implementation advances:

1. Canonical repository and release process for multi-language protobuf artifacts.
2. Supported Python version and `uv` versus Poetry.
3. License and permitted reuse level for `caas-ui` code.
4. Whether checked-in generated Python files are required or generated only in build/CI.
5. Initial history policy: memory-only versus optional SQLite in the first release.
6. Zitadel human-user roles versus development service-persona switching.
7. Exact initial server/API version compatibility policy.
8. Whether the first release is internal-only or exposed to external users.
9. Whether provider-write is enabled for the CISO persona in the default local profile.
10. The exact release/tag of `zitadel-grpc-auth` that first carries human-user and OIDC application provisioning. The ownership decision is resolved: generic support belongs in `zitadel-grpc-auth/admin`; Citius-specific ACL parsing and persona definitions remain in citius-server/citius-ui.

## 18. Deferred REST gateway plan

The existing protobuf HTTP annotations and gateway/OpenAPI generation make a REST gateway feasible. Implement it in citius-server when REST is a product requirement:

1. Add the gRPC-Gateway runtime and HTTP listener.
2. Forward `Authorization` and correlation metadata correctly.
3. Share TLS and shutdown behavior with the gRPC process.
4. Normalize gRPC errors into safe HTTP responses.
5. Configure CORS only for intended browser origins.
6. Serve/version the generated OpenAPI document.
7. Add parity tests proving REST and gRPC invoke the same authorization and service behavior.

The UI may later offer REST request examples, but its primary server-side transport remains gRPC unless a concrete deployment constraint changes that decision.

## 19. `zitadel-grpc-auth` human authentication implementation plan

This section is the focused cross-repository plan for making the three interactive UI personas possible through `zitadel-grpc-auth` without turning that module into a general-purpose web framework.

### 19.1 Scope and ownership

`zitadel-grpc-auth` owns reusable Zitadel integration for:

- Creating and reconciling machine and human users.
- Assigning project-role permissions to either user type.
- Reconciling key/policy resource metadata for either user type.
- Explicitly setting or rotating a human user's password.
- Creating and reconciling an OIDC application used by a web UI.
- Returning non-secret identifiers/configuration needed by a relying party.

It does not own:

- A username/password form.
- HTTP login, callback, or logout routes.
- Browser cookies or application sessions.
- PKCE state/verifier storage.
- UI token refresh or history.
- A Resource Owner Password Credentials grant.

Those web responsibilities remain in citius-ui. The existing gRPC server introspector requires no redesign: it already validates bearer tokens independently of whether the subject is human or machine.

### 19.2 Backward-compatible public API design

Add an explicit user kind while preserving today's zero-value behavior:

```go
type UserKind string

const (
    UserKindMachine UserKind = "machine"
    UserKindHuman   UserKind = "human"
)

type HumanUserInput struct {
    Email                  string
    GivenName              string
    FamilyName             string
    DisplayName            string
    EmailVerified          bool
    InitialPassword        string
    PasswordChangeRequired bool
}

type OnboardInput struct {
    Username     string
    DisplayName  string
    UserKind     UserKind
    Human        *HumanUserInput
    Permissions  []string
    KeyAccess    KeyAccess
    PolicyAccess PolicyAccess
}
```

Compatibility rules:

- Empty `UserKind` means machine, preserving existing callers.
- `Human` must be non-nil only for `UserKindHuman`.
- Machine onboarding continues to mint a client secret only on creation.
- Human onboarding never returns a password or client secret.
- Finding an existing user of the wrong kind is an error, never an implicit conversion.

Extend the result without changing current fields:

```go
type OnboardResult struct {
    UserID       string
    Username     string
    UserKind     UserKind
    ClientID     string // machine only
    ClientSecret string // machine only and only on creation
    Created      bool
}
```

Do not overload routine onboarding with implicit password rotation. Add a separate API:

```go
type SetHumanPasswordInput struct {
    UserID         string
    Password       string
    ChangeRequired bool
}

func (c *Client) SetHumanPassword(ctx context.Context, in SetHumanPasswordInput) error
```

`InitialPassword` is consumed only when creating a new human user. An existing human user's password changes only through `SetHumanPassword`.

### 19.3 Human-user reconciliation algorithm

Refactor `Onboard` into shared and type-specific stages:

```text
validate input
    ↓
resolve project and organization
    ↓
find user by exact username
    ├── absent + machine → create machine + mint secret
    ├── absent + human   → create human + set initial password
    ├── present, expected kind → reconcile managed profile fields
    └── present, wrong kind    → fail
    ↓
reconcile project authorizations
    ↓
reconcile key/policy metadata
    ↓
return redacted result
```

Implementation requirements:

1. Replace the current one-page `ListUsers` scan with a server-side exact-username filter when supported; otherwise implement complete pagination.
2. Detect ambiguous duplicate results and fail closed.
3. Implement `ensureMachineUser` without changing existing semantics.
4. Add `ensureHumanUser` using Zitadel's human arm of `CreateUserRequest`.
5. Require an email and initial password for new human users.
6. Make locally verified email an explicit input; do not silently mark arbitrary addresses verified.
7. Reconcile only profile fields declared as managed by the input contract.
8. Reuse `reconcileAuthorizations` and `reconcileMetadata` for both kinds.
9. Never include passwords in structured logs, wrapped errors, result values, or test failure messages.

### 19.4 Password lifecycle

Password behavior must be intentionally narrow:

- New human: initial password required and sent once during creation.
- Existing human: ordinary onboarding never changes the password.
- Rotation: requires the explicit password API and an explicit caller command/flag.
- Password-change-required: supplied during create/rotate and defaults to true outside a caller-defined local demo profile.
- Password generation and environment lookup: caller responsibility; `zitadel-grpc-auth` remains free of configuration/environment loading.
- Password validation errors: report policy failure without echoing the rejected value.
- Partial failure: if user creation succeeds but subsequent role/metadata reconciliation fails, return an error that identifies the created user ID so the caller can safely retry reconciliation.

The API must document that Go strings cannot be reliably zeroed from memory. Callers should keep password lifetime short and must not cache it in long-lived config structures.

### 19.5 OIDC web application bootstrap

The existing bootstrap creates an API application for token introspection. Add an optional OIDC application specification alongside it:

```go
type OIDCApplicationInput struct {
    Name                   string
    RedirectURIs           []string
    PostLogoutRedirectURIs []string
    DevelopmentMode        bool
    EnableRefreshTokens    bool
}

type OIDCApplicationResult struct {
    ApplicationID string
    ClientID      string
    Issuer        string
}

type BootstrapInput struct {
    ProjectName     string
    ClaimNamespace  string
    Operations      []Operation
    OIDCApplication *OIDCApplicationInput
}
```

Bootstrap behavior:

1. If `OIDCApplication` is nil, preserve existing behavior exactly.
2. Validate absolute redirect and post-logout URIs before mutation.
3. Reject insecure non-loopback HTTP URIs unless development mode is explicitly enabled and Zitadel permits them.
4. Create an OIDC Web application configured for Authorization Code with PKCE.
5. Reconcile redirect URIs, post-logout URIs, refresh-token setting, and development mode idempotently.
6. Return client/application identifiers but no unnecessary client secret for a PKCE client.
7. Do not delete operator-added redirect URIs unless the API contract explicitly selects authoritative replacement semantics. Choose and document merge versus replace before implementation.
8. Keep the existing API/introspection application separate from the UI OIDC application.

### 19.6 Claim-action compatibility

The existing action derives permissions from project-role grants and resource patterns from user metadata. Verify rather than rewrite it:

1. Issue an access token through interactive OIDC login for a human user.
2. Assert the permissions claim contains the reconciled project roles.
3. Assert allowed/denied key and policy pattern claims match metadata.
4. Assert issuer, audience, subject, username, and expiry are accepted by the existing server introspector.
5. Confirm missing metadata retains current strict/fail-closed resource behavior in Citius.
6. Audit Zitadel permissions so human users cannot write the authorization metadata projected by the action.

Only change the action script if a real human-token incompatibility is observed in this verification.

### 19.7 Revocation and deletion behavior

Generalize revocation code that assumes machine-user semantics:

- Grant revocation works identically for both kinds.
- Metadata cleanup works identically for both kinds.
- Disable and delete operations identify the exact user and verify its expected kind.
- User deletion remains an explicit destructive mode.
- Password removal is not exposed as part of ordinary grant revocation.
- Revoked/disabled human access tokens must stop passing introspection, subject to the configured introspection cache TTL; document this delay in tests and operator guidance.

### 19.8 `zitadel-grpc-auth` commit sequence

Implement one reviewable commit at a time:

#### Z1 — additive user-kind domain types

- Add `UserKind`, `HumanUserInput`, extended `OnboardInput`, and extended result fields.
- Add strict input validation.
- Preserve zero-value machine behavior.
- Add table-driven validation and compatibility tests.

Exit criterion: existing machine-user tests pass unchanged and new invalid human combinations fail before any SDK call.

#### Z2 — reliable user lookup and kind checking

- Introduce an internal exact-user lookup helper.
- Add pagination or a server-side username query.
- Detect expected/actual kind mismatches and duplicates.
- Reuse it from onboard and revoke paths.

Exit criterion: lookup is deterministic beyond the first Zitadel result page and never treats a human as a machine or vice versa.

#### Z3 — human creation and idempotent reconciliation

- Implement `ensureHumanUser`.
- Set initial password only during creation.
- Reuse project authorization and resource metadata reconciliation.
- Return a human-safe result without secrets.
- Add SDK-fake/unit tests for create and existing-user paths.

Exit criterion: rerunning identical human onboarding produces no password change and no duplicate user/grant.

#### Z4 — explicit password rotation

- Add `SetHumanPassword`.
- Validate required inputs without leaking values.
- Support the change-required flag.
- Add log-capture and error-redaction tests.

Exit criterion: password changes only through the explicit API and no test/log/result exposes it.

#### Z5 — OIDC application bootstrap

- Add OIDC input/result types.
- Implement create/read/reconcile of the UI application.
- Configure Authorization Code + PKCE and redirect/logout URIs.
- Preserve nil-input bootstrap compatibility.
- Add create, no-op rerun, and changed-configuration tests.

Exit criterion: bootstrap returns a stable OIDC client ID and converges on the requested safe configuration.

#### Z6 — revoke, documentation, and examples

- Generalize revoke/type checking.
- Update package docs and README scope language.
- Add an example that provisions a human but delegates browser login to a standard relying-party library.
- Document password lifecycle, metadata trust, cache delay, and PKCE boundaries.

Exit criterion: public documentation makes it impossible to confuse human provisioning with direct password authentication in a gRPC client.

#### Z7 — live Zitadel end-to-end coverage and release

- Provision a machine and human user in a disposable Zitadel environment.
- Obtain the human token through an authorization-code/PKCE browser test.
- Assert claims and successful gRPC introspection.
- Assert role and resource denial cases.
- Assert disable/revoke behavior with cache TTL controlled.
- Run full race/lint/test gates, tag a release, and publish release notes identifying additive APIs.

Exit criterion: a released module version supports human provisioning and OIDC app bootstrap without regressing current machine clients.

### 19.9 Citius server adoption sequence

After the auth-module release:

#### C1 — dependency and ACL schema

- Upgrade `zitadel-grpc-auth` to the released version.
- Extend `bootstrap/zitadel/setup-auth` ACL with `user_type`, human profile fields, `password_env`, and password-change-required.
- Default absent `user_type` to machine.
- Preserve strict YAML known-field and permission validation.

#### C2 — type-aware provisioning commands

- Map machine ACL entries to existing onboarding.
- Map human entries to the new human onboarding API.
- Resolve password environment variables only for new-user creation or explicit rotation.
- Add `--dry-run` and explicit `--rotate-passwords` behavior.
- Preserve generated machine client secrets and token minting; do not attempt client-credential token minting for humans.

#### C3 — generated configuration and wrapper contract

- Record human user IDs/usernames separately from machine client credentials.
- Emit the OIDC UI client ID, issuer, and configured callback/logout URIs through a non-secret output consumed by citius-ui.
- Ensure generated files containing any credential remain mode `0600` and gitignored.
- Provide a stable command for `citius-ui/scripts/provision_demo_users.sh` to invoke.

#### C4 — Citius auth integration tests

- Validate the three persona ACL definitions.
- Verify permission and resource metadata reconciliation.
- Add browser-capable human token coverage without weakening existing machine-user tests.
- Exercise CISO, producer, and consumer success/denial matrices against real Citius RPCs.

### 19.10 Citius UI adoption sequence

1. Add `demo/users.yaml` without password values.
2. Add `scripts/provision_demo_users.sh` as the safe wrapper around the canonical Citius provisioner.
3. Add `.env.example` names for three initial passwords, issuer, OIDC client ID, callback URI, and logout URI.
4. Mount Gradio under FastAPI and implement Authorization Code + PKCE using a maintained Python OIDC library.
5. Store access/refresh tokens only in the server-side session store.
6. Attach the current session access token to each Python gRPC call.
7. Implement token refresh, local and federated logout, and session replacement.
8. Show persona identity and effective claims without displaying the raw token.
9. Implement the cross-persona scenario workspace with an explicit safe-artifact allowlist.
10. Add browser tests for all three logins and positive/negative operations.

### 19.11 Cross-repository verification matrix

| Case | Expected result |
|---|---|
| Existing machine onboarding after module upgrade | No behavior change |
| New CISO human login | Policy/key governance allowed; crypto operations denied |
| New producer human login | Sign/encrypt allowed; verify/decrypt denied |
| New consumer human login | Verify/decrypt allowed; sign/encrypt denied |
| Producer/consumer on `demo-restricted-*` | Resource-level denial despite method permission |
| Missing/incorrect password | Zitadel login denied; no Citius session |
| Ordinary reprovision | Roles/metadata converge; password unchanged |
| Explicit password rotation | Old password rejected; new password accepted |
| Logout/persona switch | Previous tokens removed; safe scenario artifacts only retained |
| Disabled/revoked user | Token rejected after bounded introspection-cache delay |
| OIDC bootstrap rerun | Same client identity, converged safe configuration |

### 19.12 Completion criteria

This work is complete when:

1. `zitadel-grpc-auth` has released additive human-user and OIDC application provisioning APIs.
2. Existing machine-user callers compile and behave unchanged.
3. Routine reconciliation cannot rotate a password.
4. Passwords never appear in logs, outputs, generated configuration, or committed files.
5. Citius's setup tool provisions the three declared human personas idempotently.
6. Each human token carries the expected permission and resource claims.
7. The unchanged Citius server introspection/enforcement path accepts those tokens.
8. The UI authenticates through hosted Authorization Code + PKCE, not a direct password grant.
9. Positive, method-denial, resource-denial, logout, rotation, and revocation tests pass end to end.
