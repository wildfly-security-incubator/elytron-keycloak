/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.adapters.elytron;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.keycloak.jose.jws.JWSInput;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.evidence.Evidence;

import java.security.Principal;
import java.util.Iterator;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JwtSecurityRealm implements SecurityRealm {

    @Override
    public RealmIdentity getRealmIdentity(String name, final Principal principal, Evidence evidence) throws RealmUnavailableException {
        return new JwtRealmIdentity(evidence);
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
        return SupportLevel.UNSUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
        return SupportLevel.UNSUPPORTED;
    }

    final class JwtRealmIdentity implements RealmIdentity {

        private final BearerTokenEvidence evidence;
        private ObjectNode claims;

        JwtRealmIdentity(Evidence evidence) {
            if (isBearerTokenEvidence(evidence)) {
                this.evidence = (BearerTokenEvidence) evidence;
            } else {
                this.evidence = null;
            }
        }
        @Override
        public Principal getRealmIdentityPrincipal() {
            try {
                if (exists()) {
                    return new NamePrincipal(getClaims().get("preferred_username").textValue());
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return null;
        }

        @Override
        public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
            return isValidToken(introspectToken());
        }

        @Override
        public boolean exists() throws RealmUnavailableException {
            return getClaims() != null;
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            if (exists()) {
                return new AuthorizationIdentity() {
                    private Attributes attributes;

                    @Override
                    public Attributes getAttributes() {
                        if (this.attributes == null) {
                            Attributes attributes = new MapAttributes();

                            Iterator<String> iterator = claims.fieldNames();

                            while (iterator.hasNext()) {
                                String fieldName = iterator.next();
                                JsonNode fieldValue = claims.get(fieldName);

                                attributes.addFirst(fieldName, fieldValue.toString());
                            }

                            this.attributes = attributes;
                        }

                        return this.attributes;
                    }
                };
            }

            return null;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
            throw new RealmUnavailableException("Unsupported operation");
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
            if (BearerTokenEvidence.class.equals(evidenceType)) {
                return SupportLevel.SUPPORTED;
            }

            return SupportLevel.UNSUPPORTED;
        }

        private ObjectNode getClaims() throws RealmUnavailableException {
            if (this.claims == null) {
                ObjectNode claims = introspectToken();

                if (isValidToken(claims)) {
                    this.claims = claims;
                }
            }

            return this.claims;
        }

        private boolean isValidToken(ObjectNode claims) {
            // validations here
            return claims != null;
        }

        private ObjectNode introspectToken() throws RealmUnavailableException {
            if (this.evidence != null) {
                try {
                    JWSInput jwsInput = new JWSInput(this.evidence.getToken());

                    return (ObjectNode) new ObjectMapper().readTree(jwsInput.readContentAsString());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }

            return null;
        }

        private boolean isBearerTokenEvidence(Evidence evidence) {
            return evidence instanceof BearerTokenEvidence;
        }
    }
}
