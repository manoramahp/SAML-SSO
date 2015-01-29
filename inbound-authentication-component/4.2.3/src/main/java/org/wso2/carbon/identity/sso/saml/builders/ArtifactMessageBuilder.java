/*
 * Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.saml.builders;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.binding.artifact.AbstractSAML2Artifact;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.xml.util.DatatypeHelper;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOArtifactCache;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOArtifactCacheEntry;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOArtifactCacheKey;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOArtifactRespDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSORespDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ArtifactMessageBuilder {

    private static Log log = LogFactory.getLog(ArtifactMessageBuilder.class);

    public ArtifactMessageBuilder() {

    }

    /**
     * Build the artifact and store it in the cache along with the SAML response
     * @param samlssoRespDTO
     * @return
     * @throws IdentityException
     */
    public String buildArtifact(SAMLSSORespDTO samlssoRespDTO) throws IdentityException {

        AbstractSAML2Artifact saml2Artifact = buildArtifact();
        String artifactString = saml2Artifact.base64Encode();

        SAMLSSOArtifactCacheKey cacheKey = new SAMLSSOArtifactCacheKey(artifactString);
        SAMLSSOArtifactCacheEntry cacheEntry = new SAMLSSOArtifactCacheEntry();
        SAMLSSOArtifactRespDTO artifactRespDTO = new SAMLSSOArtifactRespDTO();
        artifactRespDTO.setSamlssoRespDTO(samlssoRespDTO);
        cacheEntry.setSamlssoArtifactRespDTO(artifactRespDTO);
        SAMLSSOArtifactCache.getInstance(SAMLSSOConstants.ARTIFACT_LIFETIME).addToCache(cacheKey, cacheEntry);

        return artifactString;
    }

    /**
     * Build the SAML V2.0 Artifact type of Type Code 0x0004
     * Artifact length : 44 bytes
     *
     * SAML V2.0 defines an artifact type of type code 0x0004
     * Identification:urn:oasis:names:tc:SAML:2.0:artifact-04
     *
     * SAML_artifact := B64(TypeCode EndpointIndex RemainingArtifact)
     * TypeCode := Byte1Byte2
     * EndpointIndex := Byte1Byte2
     *
     * TypeCode := 0x0004
     * RemainingArtifact := SourceID MessageHandle
     * SourceID := 20-byte_sequence
     * MessageHandle := 20-byte_sequence
     *
     * @return SAML V2.0 Artifact type of Type Code 0x0004
     */
    // TODO use Interface type as the return type

    public SAML2ArtifactType0004 buildArtifact() throws IdentityException {

        try {
            String issuerID = SAMLSSOUtil.getIssuer().getValue();
            int assertionConsumerServiceIndex = 0x0000;

            byte[] endpointIndex = DatatypeHelper.intToByteArray(assertionConsumerServiceIndex);
            byte[] trimmedIndex = new byte[2];
            trimmedIndex[0] = endpointIndex[2];
            trimmedIndex[1] = endpointIndex[3];

            MessageDigest sha1Digester = MessageDigest.getInstance("SHA-1");
            byte[] sourceID = sha1Digester.digest(issuerID.getBytes());
            // TODO trim/pad as necessary to make sourceID 20 bytes

            SecureRandom handleGenerator = SecureRandom.getInstance("SHA1PRNG");
            byte[] messageHandle;
            messageHandle = new byte[20];
            handleGenerator.nextBytes(messageHandle);

            return new SAML2ArtifactType0004(trimmedIndex, sourceID, messageHandle);
        } catch (NoSuchAlgorithmException e) {
            log.error("JVM does not support required cryptography algorithms: SHA-1/SHA1PRNG.", e);
            throw new InternalError("JVM does not support required cryptography algorithms: SHA-1/SHA1PRNG.");
        }
    }
}
