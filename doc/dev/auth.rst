Authentication extensions
=========================

Authentication methods own their configuration and credential verification.
They do not parse CSRs, read streams, choose challenge providers, or issue
certificates. Domain permissions and method composition belong to policies.

A method subclasses ``AuthenticationMethod`` and supplies a Pydantic ``Config``
model plus ``authenticate(context)``. Use ``StrictConfig`` to reject unknown
settings and suppress credential values in validation errors. For example,
a method for a custom shared-token client could look like this::

    import hmac

    from pydantic import SecretStr

    from macen.auth import (
        AuthenticationContext, AuthenticationMethod, AuthResult, AuthStatus,
        auth_methods,
    )
    from macen.settings import StrictConfig

    class TokenConfig(StrictConfig):
        secret: SecretStr

    class TokenMethod(AuthenticationMethod[TokenConfig]):
        Config = TokenConfig

        def authenticate(self, request: AuthenticationContext) -> AuthResult:
            supplied = request.headers.get("x-client-token")
            if supplied is None:
                return AuthResult(AuthStatus.MISSING)
            valid = hmac.compare_digest(
                supplied.encode("utf-8"),
                self.config.secret.get_secret_value().encode("utf-8"),
            )
            return AuthResult(AuthStatus.SUCCESS if valid else AuthStatus.REJECTED)

    auth_methods.register("token", TokenMethod)

Registration is the only integration step. The loader discovers and validates
``TokenMethod.Config`` and construction passes the resulting model to the method.
No parser, server, policy, or issuance changes are needed. Duplicate registrations
are errors. A separately installed module may register itself when imported
using an explicitly configured ``[setup] plugin = ["package.module"]`` in TOML
(or ``plugin=package.module`` in INI). Automatic plugin discovery is not provided.
The extension's methods use the structured TOML configuration; legacy flat INI
option translation is limited to built-in authentication methods.

Configure the example with::

    [[policies]]
    domains = ["example.org"]

    [policies.auth.token]
    secret = "replace-me"

The context contains a peer IP, a copied read-only mapping of lowercase header
names, exact request body bytes, and an optional verified ``Identity`` from the
protocol adapter. Never treat an arbitrary identity HTTP header as verified.
Methods must support concurrent calls, keep per-request state local, and use
bounded timeouts for external lookups. Constructors should avoid external effects;
validation and application construction precede listener startup.

``MISSING`` and ``REJECTED`` fail a requirement. Exceptions abort evaluation;
they never cause fallback to another policy. ``AllOf`` requires every method to
succeed, rejects empty requirements, and rejects conflicting returned identities.
An authentication class is unaware of how requirements are composed. Additional
composition nodes can be added to the evaluator and configuration layer without
changing method implementations.

Architecture and future interfaces
---------------------------------

The HTTP adapter enforces body limits and constructs authentication evidence.
``CertificateRequest`` validates and parses the CSR. ``PolicyEvaluator.authorize``
accepts identifiers independently of a CSR and returns a grant for one complete
policy. ``IssuanceService`` coordinates authorization, certificate caching, and the
upstream issuer; finalization checks the CSR identifiers against the grant.

``ChallengeRouter`` selects a provider per identifier. Providers prepare a
challenge and return a cleanup callback. The upstream manager owns cleanup on
success and all failure paths, including partial orders. DNS providers retain
multiple TXT values at the same owner name; cleanup removes only the values
owned by the completed authorizations. Runtime listener ownership belongs to
``Application``. The upstream client's mutable state and cache transactions are
serialized by the issuance service.

A future client-facing ACME adapter can verify account signatures and supply an
``Identity``, then authorize order identifiers before receiving the CSR. The
built-in ``identity`` method matches an issuer and a list of subjects. ACME
accounts, orders, nonces, EAB enrollment, and persistence are not implemented by
this refactor. Their persistence will be separate from the optional certificate
cache. Upstream challenges remain independent of client authentication.
