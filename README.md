# Keycloak SAML Attribute Group Mapper

Keycloak mapper for mapping a SAML attribute into a Keycloak group.

It combines code from [AttributeToRoleMapper.java](https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/broker/saml/mappers/AttributeToRoleMapper.java) and [AdvancedClaimToGroupMapper.java](https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/broker/oidc/mappers/AdvancedClaimToGroupMapper.java).

To make Keycloak recognize the mapper the src/main/resources/META-INF folder and its content is required.

## Build

Requirements are Maven (verified 3.6.3) and Java (verified openjdk 1.8.0_322).

To build a .jar file that can be used in Keycloak run the following command

```bash
mvn clean package
```

## Deploy

To deploy the mapper in Keycloak copy the .jar file into the `/opt/keycloak/providers` folder.

When deploying to Docker, copy the file before running `kc.sh build` in the Docker file.
