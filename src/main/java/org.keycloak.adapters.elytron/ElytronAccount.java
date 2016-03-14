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

import org.jboss.logging.Logger;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.wildfly.security.auth.server.SecurityIdentity;

import javax.security.auth.callback.CallbackHandler;
import java.security.Principal;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronAccount implements OidcKeycloakAccount {

    protected static Logger log = Logger.getLogger(ElytronAccount.class);

    private final KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal;
    private SecurityIdentity securityIdentity;

    public ElytronAccount(KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal, SecurityIdentity securityIdentity) {
        this.principal = principal;
        this.securityIdentity = securityIdentity;
    }

    @Override
    public RefreshableKeycloakSecurityContext getKeycloakSecurityContext() {
        return principal.getKeycloakSecurityContext();
    }

    @Override
    public Principal getPrincipal() {
        return principal;
    }

    @Override
    public Set<String> getRoles() {
        return securityIdentity.getRoles();
    }

    public SecurityIdentity getSecurityIdentity() {
        return this.securityIdentity;
    }

    void setCurrentRequestInfo(KeycloakDeployment deployment, AdapterTokenStore tokenStore) {
        principal.getKeycloakSecurityContext().setCurrentRequestInfo(deployment, tokenStore);
    }

    // Check if accessToken is active and try to refresh if it's not
    public boolean checkActive(CallbackHandler callbackHandler) {
        // this object may have been serialized, so we need to reset realm config/metadata
        RefreshableKeycloakSecurityContext session = getKeycloakSecurityContext();
        if (session.isActive() && !session.getDeployment().isAlwaysRefreshToken()) {
            log.debug("session is active");
            return true;
        }

        log.debug("session is not active or refresh is enforced. Try refresh");
        boolean success = session.refreshExpiredToken(false);
        if (!success || !session.isActive()) {
            log.debug("session is not active return with failure");

            return false;
        }

        log.debug("refresh succeeded");

        SecurityIdentity securityIdentity = SecurityIdentityUtil.fromAccessToken(callbackHandler, session.getTokenString());

        if (securityIdentity != null) {
            this.securityIdentity = securityIdentity;
        }

        return true;
    }
}
