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
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.RequestAuthenticator;
import org.wildfly.security.http.HttpServerSession;

import javax.security.auth.callback.CallbackHandler;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronSessionTokenStore implements AdapterTokenStore {

    private static Logger log = Logger.getLogger(ElytronSessionTokenStore.class);

    private final ElytronHttpFacade httpFacade;
    private final KeycloakDeployment deployment;
    private final CallbackHandler callbackHandler;

    public ElytronSessionTokenStore(ElytronHttpFacade httpFacade, KeycloakDeployment deployment, CallbackHandler callbackHandler) {
        this.httpFacade = httpFacade;
        this.deployment = deployment;
        this.callbackHandler = callbackHandler;
    }

    @Override
    public void checkCurrentToken() {

    }

    @Override
    public boolean isCached(RequestAuthenticator authenticator) {
        HttpServerSession session = this.httpFacade.getSession(false);

        if (session == null) {
            log.debug("session was null, returning null");
            return false;
        }

        ElytronAccount account;

        try {
            account = session.getAttribute(ElytronAccount.class.getName());
        } catch (IllegalStateException e) {
            log.debug("session was invalidated.  Return false.");
            return false;
        }
        if (account == null) {
            log.debug("Account was not in session, returning null");
            return false;
        }

        if (!deployment.getRealm().equals(account.getKeycloakSecurityContext().getRealm())) {
            log.debug("Account in session belongs to a different realm than for this request.");
            return false;
        }

        account.setCurrentRequestInfo(deployment, this);

        if (account.checkActive(this.callbackHandler)) {
            log.debug("Cached account found");
            this.httpFacade.authenticationComplete(account.getSecurityIdentity());
            restoreRequest();
            return true;
        } else {
            log.debug("Refresh failed. Account was not active. Returning null and invalidating Http session");
            try {
                session.removeAttribute(ElytronAccount.class.getName());
                session.removeAttribute(KeycloakSecurityContext.class.getName());
                session.invalidate();
            } catch (Exception e) {
                log.debug("Failed to invalidate session, might already be invalidated");
            }
            return false;
        }
    }

    @Override
    public void saveAccountInfo(OidcKeycloakAccount account) {
        HttpServerSession session = this.httpFacade.getSession(true);
        session.setAttribute(ElytronAccount.class.getName(), account);
        session.setAttribute(KeycloakSecurityContext.class.getName(), account.getKeycloakSecurityContext());
    }

    @Override
    public void logout() {
        HttpServerSession session = this.httpFacade.getSession(false);

        if (session == null) {
            return;
        }

        try {
            ElytronAccount account = session.getAttribute(ElytronAccount.class.getName());

            if (account == null) {
                return;
            }

            session.removeAttribute(KeycloakSecurityContext.class.getName());
            session.removeAttribute(ElytronAccount.class.getName());
        } catch (IllegalStateException ise) {
            // Session may be already logged-out in case that app has adminUrl
            log.debugf("Session %s logged-out already", session.getId());
        }


        if (session != null) {
            session.invalidate();
        }
    }

    @Override
    public void refreshCallback(RefreshableKeycloakSecurityContext securityContext) {

    }

    @Override
    public void saveRequest() {

    }

    @Override
    public boolean restoreRequest() {
        return false;
    }
}
