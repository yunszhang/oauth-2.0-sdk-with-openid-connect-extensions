/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.entities;


import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.federation.trust.marks.TrustMarkClaimsSet;


public class FederationEntityMetadataTest extends TestCase {
	
	
	static final SignedJWT TRUST_MARK_1;
	
	static {
		try {
			RSAKey rsaJWK = new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.generate();
			
			String trustMarkClaims = "{" +
				"\"iss\": \"https://swamid.sunet.se\"," +
				"\"sub\": \"https://umu.se/op\"," +
				"\"iat\": 1577833200," +
				"\"exp\": 1609369200," +
				"\"id\": \"https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf\"" +
				"}";
			
			TRUST_MARK_1 = new SignedJWT(
				new JWSHeader(JWSAlgorithm.RS256),
				new TrustMarkClaimsSet(JWTClaimsSet.parse(trustMarkClaims)).toJWTClaimsSet());
			TRUST_MARK_1.sign(new RSASSASigner(rsaJWK));
			
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testConstructorWithEndpoint() throws ParseException {
		
		URI fedEndpoint = URI.create("https://c2id.com/fed");
		FederationEntityMetadata metadata = new FederationEntityMetadata(fedEndpoint);
		assertEquals(fedEndpoint, metadata.getFederationAPIEndpointURI());
		
		assertNull(metadata.getTrustAnchorID());
		EntityID anchorID = new EntityID("https://federation.example.com");
		metadata.setTrustAnchorID(anchorID);
		assertEquals(anchorID, metadata.getTrustAnchorID());
		
		assertNull(metadata.getName());
		String name = "Org name";
		metadata.setName(name);
		assertEquals(name, metadata.getName());
		
		assertNull(metadata.getContacts());
		List<String> contacts = Arrays.asList("federation@c2id.com", "+359102030");
		metadata.setContacts(contacts);
		assertEquals(contacts, metadata.getContacts());
		
		assertNull(metadata.getPolicyURI());
		URI policyURI = URI.create("https://c2id.com/federation-policy.html");
		metadata.setPolicyURI(policyURI);
		assertEquals(policyURI, metadata.getPolicyURI());
		
		assertNull(metadata.getHomepageURI());
		URI homepageURI = URI.create("https://c2id.com");
		metadata.setHomepageURI(homepageURI);
		assertEquals(homepageURI, metadata.getHomepageURI());
		
		assertNull(metadata.getTrustMarks());
		metadata.setTrustMarks(Collections.singletonList(TRUST_MARK_1));
		assertEquals(Collections.singletonList(TRUST_MARK_1), metadata.getTrustMarks());
		
		JSONObject jsonObject = metadata.toJSONObject();
		assertEquals(fedEndpoint.toString(), jsonObject.get("federation_api_endpoint"));
		assertEquals(anchorID.getValue(), jsonObject.get("trust_anchor_id"));
		assertEquals(name, jsonObject.get("name"));
		assertEquals(contacts, JSONObjectUtils.getStringList(jsonObject, "contacts"));
		assertEquals(policyURI.toString(), jsonObject.get("policy_uri"));
		assertEquals(homepageURI.toString(), jsonObject.get("homepage_uri"));
		assertEquals(Collections.singletonList(TRUST_MARK_1.serialize()), JSONObjectUtils.getJSONArray(jsonObject, "trust_marks"));
		
		metadata = FederationEntityMetadata.parse(metadata.toJSONString());
		
		assertEquals(fedEndpoint, metadata.getFederationAPIEndpointURI());
		assertEquals(anchorID, metadata.getTrustAnchorID());
		assertEquals(contacts, metadata.getContacts());
		assertEquals(policyURI, metadata.getPolicyURI());
		assertEquals(homepageURI, metadata.getHomepageURI());
		assertEquals(TRUST_MARK_1.serialize(), metadata.getTrustMarks().get(0).getParsedString());
	}
	
	
	public void testConstructorWithNoEndpoint() throws ParseException {
		
		FederationEntityMetadata metadata = new FederationEntityMetadata(null);
		assertNull(metadata.getFederationAPIEndpointURI());
		
		JSONObject jsonObject = metadata.toJSONObject();
		assertTrue(jsonObject.isEmpty());
		
		String json = metadata.toJSONString();
		assertEquals("{}", json);
		
		metadata = FederationEntityMetadata.parse(json);
		
		assertNull(metadata.getFederationAPIEndpointURI());
		assertNull(metadata.getTrustAnchorID());
		assertNull(metadata.getName());
		assertNull(metadata.getContacts());
		assertNull(metadata.getPolicyURI());
		assertNull(metadata.getHomepageURI());
	}
	
	
	public void testParseExample()
		throws ParseException {
		
		String json = "{" +
			"    \"federation_api_endpoint\":" +
			"        \"https://example.com/federation_api_endpoint\"," +
			"    \"name\": \"The example cooperation\"," +
			"    \"homepage_uri\": \"https://www.example.com\"" +
			"}";
		
		FederationEntityMetadata metadata = FederationEntityMetadata.parse(json);
		
		assertEquals(URI.create("https://example.com/federation_api_endpoint"), metadata.getFederationAPIEndpointURI());
		assertEquals("The example cooperation", metadata.getName());
		assertEquals(URI.create("https://www.example.com"), metadata.getHomepageURI());
	}
}
