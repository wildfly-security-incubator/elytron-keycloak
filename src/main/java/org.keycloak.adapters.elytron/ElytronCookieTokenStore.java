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
import org.keycloak.adapters.CookieTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.spi.HttpFacade;
import org.wildfly.security.auth.server.SecurityIdentity;

import javax.security.auth.callback.CallbackHandler;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronCookieTokenStore implements AdapterTokenStore {

    protected static Logger log = Logger.getLogger(ElytronCookieTokenStore.class);

    private final HttpFacade facade;
    private final KeycloakDeployment deployment;
    private final CallbackHandler callbackHandler;

    public ElytronCookieTokenStore(HttpFacade facade, KeycloakDeployment deployment, CallbackHandler callbackHandler) {
        this.facade = facade;
        this.deployment = deployment;
        this.callbackHandler = callbackHandler;
    }

    @Override
    public void checkCurrentToken() {
        // TODO: do we need this ? Keycloak Undertow Adapter does not implement this method
    }

    @Override
    public boolean isCached(RequestAuthenticator authenticator) {
        KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal = CookieTokenStore.getPrincipalFromCookie(deployment, facade, this);

        if (principal == null) {
            log.debug("Account was not in cookie or was invalid, returning null");
            return false;
        }

        if (!deployment.getRealm().equals(principal.getKeycloakSecurityContext().getRealm())) {
            log.debug("Account in session belongs to a different realm than for this request.");
            return false;
        }

        if (principal.getKeycloakSecurityContext().isActive()) {
            SecurityIdentity securityIdentity = SecurityIdentityUtil.fromAccessToken(this.callbackHandler, principal.getKeycloakSecurityContext().getTokenString());

            if (securityIdentity != null) {
                getElytronHttpFacade().authenticationComplete(securityIdentity);
                return true;
            }
        }

        log.debug("Account was not active, removing cookie and returning false");

        logout();

        return false;
    }

    private ElytronHttpFacade getElytronHttpFacade() {
        return (ElytronHttpFacade) this.facade;
    }

    @Override
    public void saveAccountInfo(OidcKeycloakAccount account) {
        RefreshableKeycloakSecurityContext secContext = (RefreshableKeycloakSecurityContext)account.getKeycloakSecurityContext();
        CookieTokenStore.setTokenCookie(deployment, facade, secContext);
    }

    @Override
    public void logout() {
        KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal = CookieTokenStore.getPrincipalFromCookie(deployment, facade, this);

        if (principal == null) {
            return;
        }

        CookieTokenStore.removeCookie(facade);
    }

    @Override
    public void refreshCallback(RefreshableKeycloakSecurityContext securityContext) {
        CookieTokenStore.setTokenCookie(deployment, facade, securityContext);
    }

    @Override
    public void saveRequest() {

    }

    @Override
    public boolean restoreRequest() {
        return false;
    }
}
