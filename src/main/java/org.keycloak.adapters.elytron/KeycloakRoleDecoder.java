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
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.RoleDecoder;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class KeycloakRoleDecoder implements RoleDecoder {
    @Override
    public Set<String> decodeRoles(Attributes attributes) {
        Attributes.Entry realmAccess = attributes.get("realm_access");

        if (realmAccess != null) {
            String realmAccessValue = realmAccess.get(0);

            try {
                JsonNode jsonNode = new ObjectMapper().readTree(realmAccessValue);
                JsonNode roles = jsonNode.get("roles");
                Set<String> roleSet = new HashSet<>();
                Iterator<JsonNode> iterator = roles.iterator();

                while (iterator.hasNext()) {
                    roleSet.add(iterator.next().asText());
                }

                return roleSet;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return Collections.emptySet();
    }
}
