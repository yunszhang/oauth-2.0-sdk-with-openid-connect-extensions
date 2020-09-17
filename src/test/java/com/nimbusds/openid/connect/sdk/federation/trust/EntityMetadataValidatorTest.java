/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.openid.connect.sdk.federation.trust;


import java.net.URI;
import java.util.Arrays;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.sdk.federation.entities.FederationMetadataType;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;


public class EntityMetadataValidatorTest extends TestCase {


	public static class RPMetadataMustBePresentValidator implements EntityMetadataValidator {
		
		
		@Override
		public FederationMetadataType getType() {
			return FederationMetadataType.OPENID_RELYING_PARTY;
		}
		
		
		@Override
		public void validate(JSONObject metadata) throws InvalidEntityMetadataException {
		
			if (metadata == null || metadata.isEmpty()) {
				throw new InvalidEntityMetadataException("Missing required RP metadata");
			}
		}
	}
	
	
	public void testRPMetadataMustBePresentValidator() throws InvalidEntityMetadataException {
		
		RPMetadataMustBePresentValidator validator = new RPMetadataMustBePresentValidator();
		assertEquals(FederationMetadataType.OPENID_RELYING_PARTY, validator.getType());
		
		try {
			validator.validate(null);
			fail();
		} catch (InvalidEntityMetadataException e) {
			assertEquals("Missing required RP metadata", e.getMessage());
		}
		
		OIDCClientMetadata rpMetadata = new OIDCClientMetadata();
		rpMetadata.setRedirectionURI(URI.create("https://rp.example.com/cb"));
		rpMetadata.applyDefaults();
		rpMetadata.setClientRegistrationTypes(Arrays.asList(ClientRegistrationType.EXPLICIT, ClientRegistrationType.AUTOMATIC));
		
		// Pass
		validator.validate(rpMetadata.toJSONObject());
	}
}
