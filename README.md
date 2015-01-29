# SAML-SSO
This repository contains the milestone 1 deliverables of the "SAML SSO HTTP Artifact Binding support in Identity Server".
Artifact sending for SAML authentication response is implemented and added to the SAML SSO Inbound Authentication Component.

Following modifications are added to the SAML SSO Inbound Authentication Component.

1. builders package : 
      Added ArtifactBuilder.java class which is responsible for building SAML V2.0 artifacts.

2. dto package : 
      Added SAMLSSOArtifactRespDTO.java

3. cache package : 
      Added the follwing java classes to implement the cache to store artifact
      SAMLSSOArtifactCache.java
      SAMLSSOArtifactCacheKey.java
      SAMLSSOArtifactCacheEntry.java

4. processors package :
      Modified SPInitSSOAuthnRequestProcessor.java class to send the Artifact instead of the SAML Response

5. servlet package : 
      Added new method to send the Artifact in SAMLSSOProviderServlet.java class

6. Added constant values in SAMLSSOConstants.java
