package io.quarkus.oidc.runtime;

import java.io.Closeable;
import java.security.Key;
import java.time.Duration;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.jboss.logging.Logger;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.consumer.ErrorCodeValidator;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.UnresolvableKeyException;

import io.quarkus.oidc.AuthorizationCodeTokens;
import io.quarkus.oidc.OIDCException;
import io.quarkus.oidc.OidcConfigurationMetadata;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.TokenIntrospection;
import io.quarkus.oidc.UserInfo;
import io.quarkus.oidc.common.runtime.OidcConstants;
import io.quarkus.security.AuthenticationFailedException;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.mutiny.Uni;

public class OidcProvider implements Closeable {

    private static final Logger LOG = Logger.getLogger(OidcProvider.class);
    private static final String ANY_ISSUER = "any";
    private static final String[] ASYMMETRIC_SUPPORTED_ALGORITHMS = new String[] { SignatureAlgorithm.RS256.getAlgorithm(),
            SignatureAlgorithm.RS384.getAlgorithm(),
            SignatureAlgorithm.RS512.getAlgorithm(),
            SignatureAlgorithm.ES256.getAlgorithm(),
            SignatureAlgorithm.ES384.getAlgorithm(),
            SignatureAlgorithm.ES512.getAlgorithm() };
    private static final AlgorithmConstraints ASYMMETRIC_ALGORITHM_CONSTRAINTS = new AlgorithmConstraints(
            AlgorithmConstraints.ConstraintType.PERMIT, ASYMMETRIC_SUPPORTED_ALGORITHMS);
    private static final AlgorithmConstraints SYMMETRIC_ALGORITHM_CONSTRAINTS = new AlgorithmConstraints(
            AlgorithmConstraints.ConstraintType.PERMIT, SignatureAlgorithm.HS256.getAlgorithm());

    final OidcProviderClient client;
    final RefreshableVerificationKeyResolver asymmetricKeyResolver;
    final OidcTenantConfig oidcConfig;
    final String issuer;
    final String[] audience;

    public OidcProvider(OidcProviderClient client, OidcTenantConfig oidcConfig, JsonWebKeySet jwks) {
        this.client = client;
        this.oidcConfig = oidcConfig;
        this.asymmetricKeyResolver = jwks == null ? null
                : new JsonWebKeyResolver(jwks, oidcConfig.token.forcedJwkRefreshInterval);

        this.issuer = checkIssuerProp();
        this.audience = checkAudienceProp();
    }

    public OidcProvider(String publicKeyEnc, OidcTenantConfig oidcConfig) {
        this.client = null;
        this.oidcConfig = oidcConfig;
        this.asymmetricKeyResolver = new LocalPublicKeyResolver(publicKeyEnc);
        this.issuer = checkIssuerProp();
        this.audience = checkAudienceProp();
    }

    private String checkIssuerProp() {
        String issuerProp = null;
        if (oidcConfig != null) {
            issuerProp = oidcConfig.token.issuer.orElse(null);
            if (issuerProp == null && client != null) {
                issuerProp = client.getMetadata().getIssuer();
            }
        }
        return ANY_ISSUER.equals(issuerProp) ? null : issuerProp;
    }

    private String[] checkAudienceProp() {
        List<String> audienceProp = oidcConfig != null ? oidcConfig.token.audience.orElse(null) : null;
        return audienceProp != null ? audienceProp.toArray(new String[] {}) : null;
    }

    public TokenVerificationResult verifySelfSignedJwtToken(String token) throws InvalidJwtException {
        return verifyJwtTokenInternal(token, SYMMETRIC_ALGORITHM_CONSTRAINTS, new SymmetricKeyResolver());
    }

    public TokenVerificationResult verifyJwtToken(String token) throws InvalidJwtException {
        return verifyJwtTokenInternal(token, ASYMMETRIC_ALGORITHM_CONSTRAINTS, asymmetricKeyResolver);
    }

    private TokenVerificationResult verifyJwtTokenInternal(String token, AlgorithmConstraints algConstraints,
            VerificationKeyResolver verificationKeyResolver) throws InvalidJwtException {
        JwtConsumerBuilder builder = new JwtConsumerBuilder();

        builder.setVerificationKeyResolver(verificationKeyResolver);

        builder.setJwsAlgorithmConstraints(algConstraints);

        builder.setRequireExpirationTime();

        if (oidcConfig.token.iatRequired) {
            builder.setRequireIssuedAt();
        }

        if (issuer != null) {
            builder.setExpectedIssuer(issuer);
        }
        if (audience != null) {
            builder.setExpectedAudience(audience);
        } else {
            builder.setSkipDefaultAudienceValidation();
        }

        if (oidcConfig.token.lifespanGrace.isPresent()) {
            final int lifespanGrace = oidcConfig.token.lifespanGrace.getAsInt();
            builder.setAllowedClockSkewInSeconds(lifespanGrace);
        }

        builder.setRelaxVerificationKeyValidation();

        try {
            JwtConsumer jwtConsumer = builder.build();
            jwtConsumer.processToClaims(token);
        } catch (InvalidJwtException ex) {
            String detail = "";
            List<ErrorCodeValidator.Error> details = ex.getErrorDetails();
            if (!details.isEmpty()) {
                detail = details.get(0).getErrorMessage();
            }
            if (oidcConfig.clientId.isPresent()) {
                LOG.debugf("Verification of the token issued to client %s has failed: %s", oidcConfig.clientId.get(), detail);
            } else {
                LOG.debugf("Token verification has failed: %s", detail);
            }
            throw ex;
        }
        return new TokenVerificationResult(OidcUtils.decodeJwtContent(token), null);
    }

    public Uni<TokenVerificationResult> refreshJwksAndVerifyJwtToken(String token) {
        return asymmetricKeyResolver.refresh().onItem()
                .transformToUni(new Function<Void, Uni<? extends TokenVerificationResult>>() {

                    @Override
                    public Uni<? extends TokenVerificationResult> apply(Void v) {
                        try {
                            return Uni.createFrom().item(verifyJwtToken(token));
                        } catch (Throwable t) {
                            return Uni.createFrom().failure(t);
                        }
                    }

                });
    }

    public Uni<TokenIntrospection> introspectToken(String token) {
        if (client.getMetadata().getIntrospectionUri() == null) {
            LOG.debugf(
                    "Token issued to client %s can not be introspected because the introspection endpoint address is unknown - "
                            + "please check if your OpenId Connect Provider supports the token introspection",
                    oidcConfig.clientId.get());
            throw new AuthenticationFailedException();
        }
        return client.introspectToken(token).onItemOrFailure()
                .transform(new BiFunction<TokenIntrospection, Throwable, TokenIntrospection>() {

                    @Override
                    public TokenIntrospection apply(TokenIntrospection introspectionResult, Throwable t) {
                        if (t != null) {
                            throw new AuthenticationFailedException(t);
                        }
                        if (!Boolean.TRUE.equals(introspectionResult.getBoolean(OidcConstants.INTROSPECTION_TOKEN_ACTIVE))) {
                            LOG.debugf("Token issued to client %s is not active", oidcConfig.clientId.get());
                            throw new AuthenticationFailedException();
                        }
                        Long exp = introspectionResult.getLong(OidcConstants.INTROSPECTION_TOKEN_EXP);
                        if (exp != null) {
                            final int lifespanGrace = client.getOidcConfig().token.lifespanGrace.isPresent()
                                    ? client.getOidcConfig().token.lifespanGrace.getAsInt()
                                    : 0;
                            if (System.currentTimeMillis() / 1000 > exp + lifespanGrace) {
                                LOG.debugf("Token issued to client %s has expired", oidcConfig.clientId.get());
                                throw new AuthenticationFailedException();
                            }
                        }

                        return introspectionResult;
                    }

                });
    }

    public Uni<UserInfo> getUserInfo(String accessToken) {
        return client.getUserInfo(accessToken);
    }

    public Uni<AuthorizationCodeTokens> getCodeFlowTokens(String code, String redirectUri, String codeVerifier) {
        return client.getAuthorizationCodeTokens(code, redirectUri, codeVerifier);
    }

    public Uni<AuthorizationCodeTokens> refreshTokens(String refreshToken) {
        return client.refreshAuthorizationCodeTokens(refreshToken);
    }

    @Override
    public void close() {
        if (client != null) {
            client.close();
        }
    }

    private class JsonWebKeyResolver implements RefreshableVerificationKeyResolver {
        volatile JsonWebKeySet jwks;
        volatile long lastForcedRefreshTime;
        volatile long forcedJwksRefreshIntervalMilliSecs;

        JsonWebKeyResolver(JsonWebKeySet jwks, Duration forcedJwksRefreshInterval) {
            this.jwks = jwks;
            this.forcedJwksRefreshIntervalMilliSecs = forcedJwksRefreshInterval.toMillis();
        }

        @Override
        public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext)
                throws UnresolvableKeyException {
            Key key = null;

            // Try 'kid' first
            String kid = jws.getKeyIdHeaderValue();
            if (kid != null) {
                key = getKeyWithId(jws, kid);
                if (key == null) {
                    // if `kid` was set then the key must exist
                    throw new UnresolvableKeyException(String.format("JWK with kid '%s' is not available", kid));
                }
            }

            String thumbprint = null;
            if (key == null) {
                thumbprint = jws.getHeader(HeaderParameterNames.X509_CERTIFICATE_THUMBPRINT);
                if (thumbprint != null) {
                    key = getKeyWithThumbprint(jws, thumbprint);
                    if (key == null) {
                        // if only `x5t` was set then the key must exist
                        throw new UnresolvableKeyException(
                                String.format("JWK with thumprint '%s' is not available", thumbprint));
                    }
                }
            }

            if (key == null) {
                throw new UnresolvableKeyException(
                        String.format("JWK is not available, neither 'kid' nor 'x5t' token headers are set", kid));
            } else {
                return key;
            }
        }

        private Key getKeyWithId(JsonWebSignature jws, String kid) {
            if (kid != null) {
                return jwks.getKeyWithId(kid);
            } else {
                LOG.debug("Token 'kid' header is not set");
                return null;
            }
        }

        private Key getKeyWithThumbprint(JsonWebSignature jws, String thumbprint) {
            if (thumbprint != null) {
                return jwks.getKeyWithThumbprint(thumbprint);
            } else {
                LOG.debug("Token 'x5t' header is not set");
                return null;
            }
        }

        public Uni<Void> refresh() {
            final long now = System.currentTimeMillis();
            if (now > lastForcedRefreshTime + forcedJwksRefreshIntervalMilliSecs) {
                lastForcedRefreshTime = now;
                return client.getJsonWebKeySet().onItem().transformToUni(new Function<JsonWebKeySet, Uni<? extends Void>>() {

                    @Override
                    public Uni<? extends Void> apply(JsonWebKeySet t) {
                        jwks = t;
                        return Uni.createFrom().voidItem();
                    }

                });
            } else {
                return Uni.createFrom().voidItem();
            }
        }

    }

    private static class LocalPublicKeyResolver implements RefreshableVerificationKeyResolver {
        Key key;

        LocalPublicKeyResolver(String publicKeyEnc) {
            try {
                key = KeyUtils.decodePublicKey(publicKeyEnc);
            } catch (Exception ex) {
                throw new OIDCException(ex);
            }
        }

        @Override
        public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext)
                throws UnresolvableKeyException {
            return key;
        }

    }

    private class SymmetricKeyResolver implements VerificationKeyResolver {
        @Override
        public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext)
                throws UnresolvableKeyException {
            return KeyUtils.createSecretKeyFromSecret(oidcConfig.credentials.secret.get());
        }
    }

    public OidcConfigurationMetadata getMetadata() {
        return client.getMetadata();
    }

    private static interface RefreshableVerificationKeyResolver extends VerificationKeyResolver {
        default Uni<Void> refresh() {
            return Uni.createFrom().voidItem();
        }
    }
}
