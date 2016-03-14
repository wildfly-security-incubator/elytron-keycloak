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
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.NodesRegistrationManagement;
import org.keycloak.adapters.PreAuthActionsHandler;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.UserSessionManagement;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.enums.TokenStore;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerSession;

import javax.security.auth.callback.CallbackHandler;
import javax.servlet.ServletContext;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class KeycloakHttpServerAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    static Logger log = Logger.getLogger(KeycloakHttpServerAuthenticationMechanismFactory.class);
    static final String NAME = "KEYCLOAK";

    private final Map<String, ?> properties;
    private final CallbackHandler callbackHandler;

    public KeycloakHttpServerAuthenticationMechanism(Map<String, ?> properties, CallbackHandler callbackHandler) {
        this.properties = properties;
        this.callbackHandler = callbackHandler;
    }

    @Override
    public String getMechanismName() {
        return NAME;
    }

    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        // TODO: Notifications from Elytron Web API still under discussion, so we can build the deployment context during deployment and not like this.
        AdapterDeploymentContext deploymentContext = createDeploymentContext();
        NodesRegistrationManagement nodesRegistrationManagement = new NodesRegistrationManagement();
        final ElytronHttpFacade httpFacade = new ElytronHttpFacade(request);
        KeycloakDeployment deployment = deploymentContext.resolveDeployment(httpFacade);

        PreAuthActionsHandler preActions = new PreAuthActionsHandler(new UserSessionManagement() {
            @Override
            public void logoutAll() {
                Set<String> sessions = httpFacade.getSessions();
                logoutHttpSessions(sessions.stream().collect(Collectors.toList()));
            }

            @Override
            public void logoutHttpSessions(List<String> ids) {
                for (String id : ids) {
                    HttpServerSession session = httpFacade.getSession(id);

                    if (session != null) {
                        session.invalidate();
                    }
                }

            }
        }, deploymentContext, httpFacade);

        if (preActions.handleRequest()) {
            return;
        }

        if (deployment.isConfigured()) {
            nodesRegistrationManagement.tryRegister(deployment);
            AdapterTokenStore tokenStore = getTokenStore(httpFacade, deployment);
            RequestAuthenticator authenticator = new ElytronRequestAuthenticator(this.callbackHandler, httpFacade, deployment, tokenStore, getConfidentialPort(request));
            AuthOutcome outcome = authenticator.authenticate();

            if (outcome == AuthOutcome.AUTHENTICATED) {
                return;
            }

            AuthChallenge challenge = authenticator.getChallenge();

            if (challenge != null) {
                httpFacade.authenticationInProgress(challenge);
                return;
            }

            if (outcome == AuthOutcome.FAILED) {
                httpFacade.authenticationFailed();
                return;
            }
        }

        request.noAuthenticationInProgress();
    }

    private AdapterTokenStore getTokenStore(ElytronHttpFacade httpFacade, KeycloakDeployment deployment) {
        if (deployment.getTokenStore() == TokenStore.SESSION) {
            return new ElytronSessionTokenStore(httpFacade, deployment, this.callbackHandler);
        } else {
            return new ElytronCookieTokenStore(httpFacade, deployment, this.callbackHandler);
        }
    }

// TODO: Notifications from Elytron Web API still under discussion
//    protected void registerNotifications(final SecurityContext securityContext) {
//
//        final NotificationReceiver logoutReceiver = new NotificationReceiver() {
//            @Override
//            public void handleNotification(SecurityNotification notification) {
//                if (notification.getEventType() != SecurityNotification.EventType.LOGGED_OUT) return;
//
//                HttpServerExchange exchange = notification.getExchange();
//                UndertowHttpFacade facade = createFacade();
//                KeycloakDeployment deployment = deploymentContext.resolveDeployment(facade);
//                KeycloakSecurityContext ksc = exchange.getAttachment(OIDCUndertowHttpFacade.KEYCLOAK_SECURITY_CONTEXT_KEY);
//                if (ksc != null && ksc instanceof RefreshableKeycloakSecurityContext) {
//                    ((RefreshableKeycloakSecurityContext) ksc).logout(deployment);
//                }
//                AdapterTokenStore tokenStore = getTokenStore(exchange, facade, deployment, securityContext);
//                tokenStore.logout();
//            }
//        };
//
//        securityContext.registerNotificationReceiver(logoutReceiver);
//    }

// TODO: Need to check why Keycloak needs that and if we really need that info in Elytron HTTP API
    protected int getConfidentialPort(HttpServerRequest request) {
        return 8443;
    }

    private AdapterDeploymentContext createDeploymentContext() {
        Object configResolverClass = this.properties.get("keycloak.config.resolver");
        AdapterDeploymentContext deploymentContext;

        if (configResolverClass != null) {
            try {
                KeycloakConfigResolver configResolver = (KeycloakConfigResolver) Thread.currentThread().getContextClassLoader().loadClass(configResolverClass.toString()).newInstance();
                deploymentContext = new AdapterDeploymentContext(configResolver);
                log.info("Using " + configResolverClass + " to resolve Keycloak configuration on a per-request basis.");
            } catch (Exception ex) {
                log.warn("The specified resolver " + configResolverClass + " could NOT be loaded. Keycloak is unconfigured and will deny all requests. Reason: " + ex.getMessage());
                deploymentContext = new AdapterDeploymentContext(new KeycloakDeployment());
            }
        } else {
            InputStream is = getConfigInputStream(properties);
            final KeycloakDeployment deployment;
            if (is == null) {
                log.warn("No adapter configuration.  Keycloak is unconfigured and will deny all requests.");
                deployment = new KeycloakDeployment();
            } else {
                deployment = KeycloakDeploymentBuilder.build(is);
            }
            deploymentContext = new AdapterDeploymentContext(deployment);
            log.debug("Keycloak is using a per-deployment configuration.");
        }

        return deploymentContext;
    }

    private static InputStream getJSONFromServletContext(ServletContext servletContext) {
        String json = servletContext.getInitParameter(AdapterConstants.AUTH_DATA_PARAM_NAME);
        if (json == null) {
            return null;
        }
        return new ByteArrayInputStream(json.getBytes());
    }

    private static InputStream getConfigInputStream(Map<String, ?> properties) {
//        InputStream is = getJSONFromServletContext(context);
//        if (is == null) {
//            String path = context.getInitParameter("keycloak.config.file");
//            if (path == null) {
//                log.debug("using /WEB-INF/keycloak.json");
//                is = context.getResourceAsStream("/WEB-INF/keycloak.json");
//            } else {
//                try {
//                    is = new FileInputStream(path);
//                } catch (FileNotFoundException e) {
//                    throw new RuntimeException(e);
//                }
//            }
//        }
//        return is;
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("keycloak.json");

        if (inputStream != null) {
            return inputStream;
        }

        try {
            return new FileInputStream("/tmp/keycloak-console.json");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}
