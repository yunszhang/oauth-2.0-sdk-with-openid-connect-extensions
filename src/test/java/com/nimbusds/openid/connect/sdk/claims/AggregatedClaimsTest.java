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

package com.nimbusds.openid.connect.sdk.claims;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


public class AggregatedClaimsTest extends TestCase {
	
	
	static final KeyPair RSA_KEY_PAIR;
	
	
	static {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(2048);
			RSA_KEY_PAIR = gen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	
	static JWT createClaimsJWT() {
		
		JSONObject claims = new JSONObject();
		claims.put("email", "alice@wonderland.net");
		claims.put("email_verified", true);
		return createClaimsJWT(claims);
	}
	
	
	static JWT createClaimsJWT(final JSONObject claims) {
		
		try {
			SignedJWT jwt = new SignedJWT(
				new JWSHeader(JWSAlgorithm.RS256),
				JWTClaimsSet.parse(claims)
			);
			
			jwt.sign(new RSASSASigner(RSA_KEY_PAIR.getPrivate()));
			
			return jwt;
		
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	

	public void testMinConstructor() {
		
		Set<String> claimNames = new HashSet<>(Arrays.asList("email", "email_verified"));
		JWT claimsJWT = createClaimsJWT();
	
		AggregatedClaims aggregatedClaims = new AggregatedClaims(claimNames, claimsJWT);
		
		UUID sourceUUID = UUID.fromString(aggregatedClaims.getSourceID());
		assertNotNull(sourceUUID);
		
		assertEquals(claimNames, aggregatedClaims.getNames());
		assertEquals(claimsJWT, aggregatedClaims.getClaimsJWT());
		
		JSONObject claimsJSONObject = new JSONObject();
		aggregatedClaims.mergeInto(claimsJSONObject);
		
		JSONObject claimNamesJSONObject = (JSONObject)claimsJSONObject.get("_claim_names");
		assertEquals(sourceUUID.toString(), claimNamesJSONObject.get("email"));
		assertEquals(sourceUUID.toString(), claimNamesJSONObject.get("email_verified"));
		assertEquals(2, claimNamesJSONObject.size());
		
		JSONObject claimSourcesJSONObject = (JSONObject)claimsJSONObject.get("_claim_sources");
		JSONObject claimsSourceSpec = (JSONObject)claimSourcesJSONObject.get(sourceUUID.toString());
		assertEquals(claimsJWT.serialize(), claimsSourceSpec.get("JWT"));
		assertEquals(1, claimsSourceSpec.size());
		
		assertEquals(1, claimSourcesJSONObject.size());
		
		assertEquals(2, claimsJSONObject.size());
	}
	

	public void testMainConstructor() {
		
		String sourceID = "src1";
		Set<String> claimNames = new HashSet<>(Arrays.asList("email", "email_verified"));
		JWT claimsJWT = createClaimsJWT();
	
		AggregatedClaims aggregatedClaims = new AggregatedClaims(sourceID, claimNames, claimsJWT);
		
		assertEquals(sourceID, aggregatedClaims.getSourceID());
		assertEquals(claimNames, aggregatedClaims.getNames());
		assertEquals(claimsJWT, aggregatedClaims.getClaimsJWT());
		
		JSONObject claimsJSONObject = new JSONObject();
		aggregatedClaims.mergeInto(claimsJSONObject);
		
		JSONObject claimNamesJSONObject = (JSONObject)claimsJSONObject.get("_claim_names");
		assertEquals(sourceID, claimNamesJSONObject.get("email"));
		assertEquals(sourceID, claimNamesJSONObject.get("email_verified"));
		assertEquals(2, claimNamesJSONObject.size());
		
		JSONObject claimSourcesJSONObject = (JSONObject)claimsJSONObject.get("_claim_sources");
		JSONObject claimsSourceSpec = (JSONObject)claimSourcesJSONObject.get(sourceID.toString());
		assertEquals(claimsJWT.serialize(), claimsSourceSpec.get("JWT"));
		assertEquals(1, claimsSourceSpec.size());
		
		assertEquals(1, claimSourcesJSONObject.size());
		
		assertEquals(2, claimsJSONObject.size());
	}
	
	
	public void testMergeTwoSources() {
		
		String src1 = "src1";
		
		JSONObject claims1 = new JSONObject();
		claims1.put("email", "alice@wonderland.net");
		claims1.put("email_verified", true);
		
		JWT jwt1 = createClaimsJWT(claims1);
		
		AggregatedClaims aggregatedClaims1 = new AggregatedClaims(
			src1,
			claims1.keySet(),
			jwt1);
		
		assertEquals(src1, aggregatedClaims1.getSourceID());
		assertEquals(claims1.keySet(), aggregatedClaims1.getNames());
		assertEquals(jwt1.serialize(), aggregatedClaims1.getClaimsJWT().serialize());
		
		JSONObject jsonObject = new JSONObject();
		aggregatedClaims1.mergeInto(jsonObject);
		
		String src2 = "src2";
		
		JSONObject claims2 = new JSONObject();
		claims2.put("score", "100");
		
		JWT jwt2 = createClaimsJWT(claims2);
		
		AggregatedClaims aggregatedClaims2 = new AggregatedClaims(
			src2,
			claims2.keySet(),
			jwt2);
		
		assertEquals(src2, aggregatedClaims2.getSourceID());
		assertEquals(claims2.keySet(), aggregatedClaims2.getNames());
		assertEquals(jwt2.serialize(), aggregatedClaims2.getClaimsJWT().serialize());
		
		aggregatedClaims2.mergeInto(jsonObject);
		
		JSONObject claimNamesJSONObject = (JSONObject)jsonObject.get("_claim_names");
		assertEquals(src1, claimNamesJSONObject.get("email"));
		assertEquals(src1, claimNamesJSONObject.get("email_verified"));
		assertEquals(src2, claimNamesJSONObject.get("score"));
		assertEquals(3, claimNamesJSONObject.size());
		
		JSONObject claimSourcesJSONObject = (JSONObject)jsonObject.get("_claim_sources");
		JSONObject claimsSource1Spec = (JSONObject)claimSourcesJSONObject.get(src1);
		assertEquals(jwt1.serialize(), claimsSource1Spec.get("JWT"));
		assertEquals(1, claimsSource1Spec.size());
		JSONObject claimsSource2Spec = (JSONObject)claimSourcesJSONObject.get(src2);
		assertEquals(jwt2.serialize(), claimsSource2Spec.get("JWT"));
		assertEquals(1, claimsSource2Spec.size());
		
		assertEquals(2, claimSourcesJSONObject.size());
		
		assertEquals(2, jsonObject.size());
	}
	
	
	public void testRejectNullSourceID() {
		
		try {
			new AggregatedClaims(null, Collections.singleton("score"), createClaimsJWT());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The claims source identifier must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testRejectEmptySourceID() {
		
		try {
			new AggregatedClaims("", Collections.singleton("score"), createClaimsJWT());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The claims source identifier must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testRejectNullClaimNames() {
		
		try {
			new AggregatedClaims("src1", null, createClaimsJWT());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The claim names must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testRejectEmptyClaimNames() {
		
		try {
			new AggregatedClaims("src1", Collections.<String>emptySet(), createClaimsJWT());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The claim names must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testRejectNullJWT() {
		
		try {
			new AggregatedClaims("src1", Collections.singleton("score"), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The claims JWT must not be null", e.getMessage());
		}
	}
}
