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

import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthenticationError;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.spi.LogoutError;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.http.HttpServerSession;

import javax.security.cert.X509Certificate;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class ElytronHttpFacade implements HttpFacade {

    private final HttpServerRequest request;
    private Consumer<HttpServerResponse> responseConsumer;

    public ElytronHttpFacade(HttpServerRequest request) {
        this.request = request;
        this.responseConsumer = response -> {};
    }

    @Override
    public Request getRequest() {
        return new Request() {
            @Override
            public String getMethod() {
                return request.getRequestMethod();
            }

            @Override
            public String getURI() {
                return request.getRequestURI();
            }

            @Override
            public boolean isSecure() {
                return request.getRequestURI().toLowerCase().startsWith("https");
            }

            @Override
            public String getFirstParam(String param) {
                throw new RuntimeException("Not implemented.");
            }

            @Override
            public String getQueryParamValue(String param) {
                String[] values = request.getParameters().get(param);

                if (values != null && values.length > 0) {
                    return values[0];
                }

                return null;
            }

            @Override
            public Cookie getCookie(final String cookieName) {
                HttpServerCookie[] cookies = request.getCookies();

                if (cookies != null) {
                    for (HttpServerCookie cookie : cookies) {
                        if (cookie.getName().equals(cookieName)) {
                            return new Cookie(cookie.getName(), cookie.getValue(), cookie.getVersion(), cookie.getDomain(), cookie.getPath());
                        }
                    }
                }

                return null;
            }

            @Override
            public String getHeader(String name) {
                return request.getFirstRequestHeaderValue(name);
            }

            @Override
            public List<String> getHeaders(String name) {
                return request.getRequestHeaderValues(name);
            }

            @Override
            public InputStream getInputStream() {
                return request.getInputStream();
            }

            @Override
            public String getRemoteAddr() {
                InetSocketAddress sourceAddress = request.getSourceAddress();
                if (sourceAddress == null) {
                    return "";
                }
                InetAddress address = sourceAddress.getAddress();
                if (address == null) {
                    // this is unresolved, so we just return the host name not exactly spec, but if the name should be
                    // resolved then a PeerNameResolvingHandler should be used and this is probably better than just
                    // returning null
                    return sourceAddress.getHostString();
                }
                return address.getHostAddress();
            }

            @Override
            public void setError(AuthenticationError error) {

            }

            @Override
            public void setError(LogoutError error) {

            }
        };
    }

    @Override
    public Response getResponse() {
        return new Response() {
            @Override
            public void setStatus(final int status) {
                responseConsumer = responseConsumer.andThen(response -> response.setResponseCode(status));
            }

            @Override
            public void addHeader(final String name, final String value) {
                responseConsumer = responseConsumer.andThen(response -> response.addResponseHeader(name, value));
            }

            @Override
            public void setHeader(String name, String value) {
                addHeader(name, value);
            }

            @Override
            public void resetCookie(final String name, final String path) {
                setCookie(name, null, path, null, 0, false, false);
            }

            @Override
            public void setCookie(final String name, final String value, final String path, final String domain, final int maxAge, final boolean secure, final boolean httpOnly) {
                responseConsumer = responseConsumer.andThen(response -> response.setResponseCookie(new HttpServerCookie() {
                    @Override
                    public String getName() {
                        return name;
                    }

                    @Override
                    public String getValue() {
                        return value;
                    }

                    @Override
                    public String getDomain() {
                        return domain;
                    }

                    @Override
                    public int getMaxAge() {
                        return maxAge;
                    }

                    @Override
                    public String getPath() {
                        return path;
                    }

                    @Override
                    public boolean isSecure() {
                        return secure;
                    }

                    @Override
                    public int getVersion() {
                        return 0;
                    }

                    @Override
                    public boolean isHttpOnly() {
                        return httpOnly;
                    }
                }));
            }

            @Override
            public OutputStream getOutputStream() {
                return new ByteArrayOutputStream();
            }

            @Override
            public void sendError(int code) {
                setStatus(code);
            }

            @Override
            public void sendError(final int code, final String message) {
                responseConsumer = responseConsumer.andThen(response -> {
                    response.setResponseCode(code);
                    response.addResponseHeader("Content-Type", "text/html");
                    try {
                        response.getOutputStream().write(message.getBytes());
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
            }

            @Override
            public void end() {
            }
        };
    }

    @Override
    public X509Certificate[] getCertificateChain() {
        return new X509Certificate[0];
    }

    public void authenticationComplete(SecurityIdentity securityIdentity) {
        this.request.authenticationComplete(securityIdentity);
    }

    public void authenticationFailed() {
        this.request.authenticationFailed("Authentication Failed", response -> responseConsumer.accept(response));
    }

    public void authenticationInProgress(AuthChallenge challenge) {
        if (challenge != null) {
            challenge.challenge(ElytronHttpFacade.this);
        }
        this.request.authenticationInProgress(response -> responseConsumer.accept(response));
    }

    public void authenticationInProgress() {
        authenticationInProgress(null);
    }

    public HttpServerSession getSession(boolean create) {
        return request.getSession(create);
    }

    public HttpServerSession getSession(String id) {
        return request.getSession(id);
    }

    public Set<String> getSessions() {
        return request.getSessions();
    }
}
