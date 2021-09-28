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


import java.util.Arrays;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;


public class AccessTokenHashTest extends TestCase {


	public void testComputeAgainstSpecExample() {

		AccessToken token = new TypelessAccessToken("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y");

		AccessTokenHash computedHash = AccessTokenHash.compute(token, JWSAlgorithm.RS256);
		
		assertNotNull(computedHash);

		AccessTokenHash expectedHash = new AccessTokenHash("77QmUPtjPfzWtF2AnpK9RQ");

		assertEquals(expectedHash.getValue(), computedHash.getValue());
	}
	
	
	// https://bitbucket.org/openid/connect/issues/1125/_hash-algorithm-for-eddsa-id-tokens#comment-57040192
	public void testComputeWithSHA256() {
		
		AccessToken token = new TypelessAccessToken("YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL");
		
		AccessTokenHash expectedHash = new AccessTokenHash("xsZZrUssMXjL3FBlzoSh2g");
		
		for (JWSAlgorithm jwsAlgorithm: Arrays.asList(
			JWSAlgorithm.HS256,
			JWSAlgorithm.RS256,
			JWSAlgorithm.PS256,
			JWSAlgorithm.ES256,
			JWSAlgorithm.ES256K)) {
			
			assertEquals(expectedHash, AccessTokenHash.compute(token, jwsAlgorithm));
		}
	}
	
	
	// https://bitbucket.org/openid/connect/issues/1125/_hash-algorithm-for-eddsa-id-tokens#comment-57040192
	public void testComputeWithSHA384() {
		
		AccessToken token = new TypelessAccessToken("YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL");
		
		AccessTokenHash expectedHash = new AccessTokenHash("adt46pcdiB-l6eTNifgoVM-5AIJAxq84");
		
		for (JWSAlgorithm jwsAlgorithm: Arrays.asList(
			JWSAlgorithm.HS384,
			JWSAlgorithm.RS384,
			JWSAlgorithm.PS384,
			JWSAlgorithm.ES384)) {
			
			assertEquals(expectedHash, AccessTokenHash.compute(token, jwsAlgorithm));
		}
	}
	
	
	// https://bitbucket.org/openid/connect/issues/1125/_hash-algorithm-for-eddsa-id-tokens#comment-57040192
	public void testComputeWithSHA512() {
		
		AccessToken token = new TypelessAccessToken("YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL");
		
		AccessTokenHash expectedHash = new AccessTokenHash("p2LHG4H-8pYDc0hyVOo3iIHvZJUqe9tbj3jESOuXbkY");
		
		for (JWSAlgorithm jwsAlgorithm: Arrays.asList(
			JWSAlgorithm.HS512,
			JWSAlgorithm.RS512,
			JWSAlgorithm.PS512,
			JWSAlgorithm.ES512)) {
			
			assertEquals(expectedHash, AccessTokenHash.compute(token, jwsAlgorithm));
		}
	}


	public void testEquality() {

		AccessToken token = new TypelessAccessToken("12345678");

		AccessTokenHash hash1 = AccessTokenHash.compute(token, JWSAlgorithm.HS512);

		AccessTokenHash hash2 = AccessTokenHash.compute(token, JWSAlgorithm.HS512);
		
		assertNotNull(hash1);
		
		assertNotNull(hash2);
		
		assertEquals(hash1, hash2);
	}


	public void testUnsupportedJWSAlg() {

		AccessToken token = new TypelessAccessToken("12345678");

		assertNull(AccessTokenHash.compute(token, new JWSAlgorithm("no-such-alg")));
	}


	public void testIDTokenRequirement()
		throws Exception {

		// code flow
		// http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
		assertFalse(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("code")));

		// implicit flow
		// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken
		assertFalse(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("id_token")));
		assertTrue(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("id_token token")));

		// hybrid flow
		// http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
		assertFalse(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("code id_token")));
		assertFalse(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("code token")));
		assertTrue(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("code id_token token")));
	}
}
