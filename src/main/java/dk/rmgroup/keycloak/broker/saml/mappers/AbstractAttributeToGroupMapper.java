/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Original https://raw.githubusercontent.com/keycloak/keycloak/19.0.2/services/src/main/java/org/keycloak/broker/saml/mappers/AbstractAttributeToRoleMapper.java
 * Modified by doj@rm-group.dk Oktober 2022, changes include refactoring variable names and comments and mixing in code from https://raw.githubusercontent.com/keycloak/keycloak/19.0.2/services/src/main/java/org/keycloak/broker/oidc/mappers/AdvancedClaimToGroupMapper.java
 * to get groups instead of roles
 */

 /*
 * Original https://raw.githubusercontent.com/keycloak/keycloak/19.0.2/services/src/main/java/org/keycloak/broker/saml/mappers/AbstractAttributeToRoleMapper.java
 * Modified by doj@rm-group.dk Oktober 2022
 * Changes include refactoring variable names and comments and mixing in code from
 * https://raw.githubusercontent.com/keycloak/keycloak/19.0.2/services/src/main/java/org/keycloak/broker/oidc/mappers/AdvancedClaimToGroupMapper.java
 * to get groups instead of roles
 */

package dk.rmgroup.keycloak.broker.saml.mappers;

import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.ConfigConstants;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;

/**
 * Abstract class that handles the logic for importing and updating brokered users for all mappers that map a SAML
 * attribute into a {@code Keycloak} group.
 *
 * Original @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public abstract class AbstractAttributeToGroupMapper extends AbstractIdentityProviderMapper {

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        GroupModel group = this.getGroup(realm, mapperModel);
        if (this.applies(mapperModel, context)) {
            user.joinGroup(group);
        }
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        GroupModel group = this.getGroup(realm, mapperModel);
        String groupId = mapperModel.getConfig().get(ConfigConstants.GROUP);

        if (!context.hasMapperAssignedGroup(groupId)) {
            if (applies(mapperModel, context)) {
                context.addMapperAssignedGroup(groupId);
                user.joinGroup(group);
            } else {
                user.leaveGroup(group);
            }
        }
    }

    /**
     * This method must be implemented by subclasses and they must return {@code true} if their mapping can be applied
     * (i.e. user has the SAML attribute that should be mapped) or {@code false} otherwise.
     *
     * @param mapperModel a reference to the {@link IdentityProviderMapperModel}.
     * @param context a reference to the {@link BrokeredIdentityContext}.
     * @return {@code true} if the mapping can be applied or {@code false} otherwise.
     */
    protected abstract boolean applies(final IdentityProviderMapperModel mapperModel, final BrokeredIdentityContext context);

    /**
     * Obtains the {@link GroupModel} corresponding the group configured in the specified
     * {@link IdentityProviderMapperModel}.
     * If the group doesn't exist, this method throws an {@link IdentityBrokerException}.
     *
     * @param realm a reference to the realm.
     * @param mapperModel a reference to the {@link IdentityProviderMapperModel} containing the configured group.
     * @return the {@link GroupModel}
     * @throws IdentityBrokerException if the group doesn't exist.
     */
    private GroupModel getGroup(final RealmModel realm, final IdentityProviderMapperModel mapperModel) {
        GroupModel group = KeycloakModelUtils.findGroupByPath(realm, mapperModel.getConfig().get(ConfigConstants.GROUP));

        if (group == null) {
            throw new IdentityBrokerException("Unable to find group: " + group.getId());
        }
        return group;
    }
}
