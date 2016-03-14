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

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.SecurityIdentityCallback;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.evidence.BearerTokenEvidence;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
final class SecurityIdentityUtil {

    static SecurityIdentity fromAccessToken(CallbackHandler callbackHandler, String accessToken) {
        try {
            EvidenceVerifyCallback evidenceVerifyCallback = new EvidenceVerifyCallback(new BearerTokenEvidence(accessToken));

            callbackHandler.handle(new Callback[]{evidenceVerifyCallback});

            if (evidenceVerifyCallback.isVerified()) {
                SecurityIdentityCallback securityIdentityCallback = new SecurityIdentityCallback();

                callbackHandler.handle(new Callback[]{AuthenticationCompleteCallback.SUCCEEDED, securityIdentityCallback});

                return securityIdentityCallback.getSecurityIdentity();
            }
        } catch (UnsupportedCallbackException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return null;
    }

}
