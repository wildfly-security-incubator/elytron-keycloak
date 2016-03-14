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

import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OAuthRequestAuthenticator;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.RequestAuthenticator;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.http.HttpServerSession;

import javax.security.auth.callback.CallbackHandler;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronRequestAuthenticator extends RequestAuthenticator {

    private final CallbackHandler callbackHandler;

    public ElytronRequestAuthenticator(CallbackHandler callbackHandler, ElytronHttpFacade facade, KeycloakDeployment deployment, AdapterTokenStore tokenStore, int sslRedirectPort) {
        super(facade, deployment, tokenStore, sslRedirectPort);
        this.callbackHandler = callbackHandler;
    }

    @Override
    protected OAuthRequestAuthenticator createOAuthAuthenticator() {
        return new OAuthRequestAuthenticator(this, facade, deployment, sslRedirectPort, tokenStore);
    }

    @Override
    protected void completeOAuthAuthentication(final KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal) {
        SecurityIdentity securityIdentity = SecurityIdentityUtil.fromAccessToken(this.callbackHandler, principal.getKeycloakSecurityContext().getTokenString());

        if (securityIdentity != null) {
            this.tokenStore.saveAccountInfo(new ElytronAccount(principal, securityIdentity));
            getElytronHttpFacade().authenticationInProgress();
        }
    }

    @Override
    protected void completeBearerAuthentication(KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal, String method) {
        SecurityIdentity securityIdentity = SecurityIdentityUtil.fromAccessToken(this.callbackHandler, principal.getKeycloakSecurityContext().getTokenString());

        if (securityIdentity != null) {
            getElytronHttpFacade().authenticationComplete(securityIdentity);
        }
    }

    @Override
    protected String changeHttpSessionId(boolean create) {
        HttpServerSession session = getElytronHttpFacade().getSession(create);

        return session != null ? session.getId() : null;
    }

    private ElytronHttpFacade getElytronHttpFacade() {
        return (ElytronHttpFacade) facade;
    }
}
