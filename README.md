# SAML-SSO
This repository contains the milestone 1 deliverables of the "SAML SSO HTTP Artifact Binding support in Identity Server".
Artifact sending for SAML authentication response is implemented and added to the SAML SSO Inbound Authentication Component.

Following modifications are added to the SAML SSO Inbound Authentication Component.

1. builders
      Added ArtifactBuilder.java class which is responsible for building SAML V2.0 artifacts.

2. dto
      Added SAMLSSOArtifactRespDTO.java

3. cache
      Added the follwing java classes to implement the cache to store artifact
      SAMLSSOArtifactCache.java
      SAMLSSOArtifactCacheKey.java
      SAMLSSOArtifactCacheEntry.java

4. processors
      Modified SPInitSSOAuthnRequestProcessor.java class to send the Artifact instead of the SAML Response

5. servlet
      Added new method to send the Artifact in SAMLSSOProviderServlet.java class

6. Added constant values in SAMLSSOConstants.java
