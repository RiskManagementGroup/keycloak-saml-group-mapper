/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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
 * Original https://raw.githubusercontent.com/keycloak/keycloak/19.0.2/services/src/main/java/org/keycloak/broker/saml/mappers/AttributeToRoleMapper.java
 * Modified by doj@rm-group.dk Oktober 2022
 * Changes include refactoring variable names and comments
 */

package dk.rmgroup.keycloak.broker.saml.mappers;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.ConfigConstants;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.metadata.AttributeConsumingServiceType;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.dom.saml.v2.metadata.RequestedAttributeType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.protocol.saml.mappers.SamlMetadataDescriptorUpdater;
import org.keycloak.provider.ProviderConfigProperty;
import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.ATTRIBUTE_FORMAT_BASIC;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Original @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * Mapper that decodes Base64 encoded SAML attributes and maps them to groups.
 * @version $Revision: 1 $
 */
public class Base64DecodeAttributeToGroupMapper extends AbstractAttributeToGroupMapper implements SamlMetadataDescriptorUpdater {

    protected static final String[] COMPATIBLE_PROVIDERS = { SAMLIdentityProviderFactory.PROVIDER_ID };

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    private static final Logger logger = Logger.getLogger(Base64DecodeAttributeToGroupMapper.class);

    public static final String ATTRIBUTE_BASE64_NAME = "attribute.base64.name";
    public static final String ATTRIBUTE_BASE64_FRIENDLY_NAME = "attribute.base64.friendly.name";
    public static final String NODE_TYPE = "node.type";
    public static final String NODE_VALUE = "node.value";

    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES = new HashSet<>(
            Arrays.asList(IdentityProviderSyncMode.values()));

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_BASE64_NAME);
        property.setLabel("Base64 Encoded Attribute Name");
        property.setHelpText(
                "Name of base64 encoded attribute to search for in assertion.  You can leave this blank and specify a friendly name instead.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_BASE64_FRIENDLY_NAME);
        property.setLabel("Base64 Encoded Attribute Friendly Name");
        property.setHelpText(
                "Friendly name of base64 encoded attribute to search for in assertion.  You can leave this blank and specify a name instead.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(NODE_TYPE);
        property.setLabel("Node Type");
        property.setHelpText(
                "Type of node to search for in the decoded xml.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(NODE_VALUE);
        property.setLabel("Node Value");
        property.setHelpText(
                "Value the node must have.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ConfigConstants.GROUP);
        property.setLabel("Group");
        property.setHelpText("Group to assign the user to if attribute exists.");
        property.setType(ProviderConfigProperty.GROUP_TYPE);
        configProperties.add(property);
    }

    public static final String PROVIDER_ID = "saml-base64-decode-group-idp-mapper";

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return IDENTITY_PROVIDER_SYNC_MODES.contains(syncMode);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Group Mapper";
    }

    @Override
    public String getDisplayType() {
        return "SAML Base64 Decoded Attribute to Group";
    }

    @Override
    protected boolean applies(final IdentityProviderMapperModel mapperModel, final BrokeredIdentityContext context) {
        String base64Name = mapperModel.getConfig().get(ATTRIBUTE_BASE64_NAME);
        if (base64Name != null && base64Name.trim().equals(""))
            base64Name = null;
        String base64Friendly = mapperModel.getConfig().get(ATTRIBUTE_BASE64_FRIENDLY_NAME);
        if (base64Friendly != null && base64Friendly.trim().equals(""))
            base64Friendly = null;
        String nodeType = mapperModel.getConfig().get(NODE_TYPE);
        if (nodeType != null && nodeType.trim().equals(""))
            nodeType = null;
        String value = mapperModel.getConfig().get(NODE_VALUE);
        if (value != null && value.trim().equals(""))
            value = null;
        AssertionType assertion = (AssertionType) context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
        for (AttributeStatementType statement : assertion.getAttributeStatements()) {
            for (AttributeStatementType.ASTChoiceType choice : statement.getAttributes()) {
                AttributeType attr = choice.getAttribute();
                if (base64Name != null && !base64Name.equals(attr.getName()))
                    continue;
                if (base64Friendly != null && !base64Friendly.equals(attr.getFriendlyName()))
                    continue;

                try {
                    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                    DocumentBuilder builder = factory.newDocumentBuilder();

                    byte[] decodedBytes = Base64.getDecoder().decode((String) attr.getAttributeValue().get(0));

                    Document document = builder.parse(new ByteArrayInputStream(decodedBytes));

                    NodeList nodeList = document.getElementsByTagName(nodeType);

                    for (int i = 0; i < nodeList.getLength(); i++) {
                        Node node = nodeList.item(i);
                        if (value != null && node.getTextContent().equals(value)) {
                            return true;
                        }
                    }


                } catch (Exception e) {
                    logger.errorf(e, "Failed to parse decoded Base64 attribute");
                }
            }
        }
        return false;
    }

    @Override
    public String getHelpText() {
        return "If a base64 decoded attribute exists, assign the user to the specified group.";
    }

    // SamlMetadataDescriptorUpdater interface
    @Override
    public void updateMetadata(IdentityProviderMapperModel mapperModel, EntityDescriptorType entityDescriptor) {
        String attributeName = mapperModel.getConfig().get(ATTRIBUTE_BASE64_NAME);
        String attributeFriendlyName = mapperModel.getConfig().get(ATTRIBUTE_BASE64_FRIENDLY_NAME);

        RequestedAttributeType requestedAttribute = new RequestedAttributeType(
                mapperModel.getConfig().get(ATTRIBUTE_BASE64_NAME));
        requestedAttribute.setIsRequired(null);
        requestedAttribute.setNameFormat(ATTRIBUTE_FORMAT_BASIC.get());

        if (attributeFriendlyName != null && !attributeFriendlyName.isEmpty())
            requestedAttribute.setFriendlyName(attributeFriendlyName);

        // Add the requestedAttribute item to any AttributeConsumingServices
        for (EntityDescriptorType.EDTChoiceType choiceType : entityDescriptor.getChoiceType()) {
            List<EntityDescriptorType.EDTDescriptorChoiceType> descriptors = choiceType.getDescriptors();
            for (EntityDescriptorType.EDTDescriptorChoiceType descriptor : descriptors) {
                for (AttributeConsumingServiceType attributeConsumingService : descriptor.getSpDescriptor()
                        .getAttributeConsumingService()) {
                    boolean alreadyPresent = attributeConsumingService.getRequestedAttribute().stream()
                            .anyMatch(t -> (attributeName == null || attributeName.equalsIgnoreCase(t.getName())) &&
                                    (attributeFriendlyName == null
                                            || attributeFriendlyName.equalsIgnoreCase(t.getFriendlyName())));

                    if (!alreadyPresent)
                        attributeConsumingService.addRequestedAttribute(requestedAttribute);
                }
            }
        }
    }
}
