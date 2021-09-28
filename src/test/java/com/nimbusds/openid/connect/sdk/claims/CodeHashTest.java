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
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseType;


public class CodeHashTest extends TestCase {


	public void testComputeAgainstSpecExample() {
		
		AuthorizationCode code = new AuthorizationCode("Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk");

		assertEquals(new CodeHash("LDktKdoQak3Pk0cnXxCltA"), CodeHash.compute(code, JWSAlgorithm.RS256));
		assertEquals(new CodeHash("LDktKdoQak3Pk0cnXxCltA"), CodeHash.compute(code, JWSAlgorithm.RS256, null));
	}
	
	
	// https://bitbucket.org/openid/connect/issues/1125/_hash-algorithm-for-eddsa-id-tokens#comment-57040192
	public void testComputeWithSHA256() {
		
		AuthorizationCode code = new AuthorizationCode("YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL");
		
		CodeHash expectedHash = new CodeHash("xsZZrUssMXjL3FBlzoSh2g");
		
		for (JWSAlgorithm jwsAlgorithm: Arrays.asList(
			JWSAlgorithm.HS256,
			JWSAlgorithm.RS256,
			JWSAlgorithm.PS256,
			JWSAlgorithm.ES256,
			JWSAlgorithm.ES256K)) {
			
			assertEquals(expectedHash, CodeHash.compute(code, jwsAlgorithm));
			assertEquals(expectedHash, CodeHash.compute(code, jwsAlgorithm, null));
		}
	}
	
	
	// https://bitbucket.org/openid/connect/issues/1125/_hash-algorithm-for-eddsa-id-tokens#comment-57040192
	public void testComputeWithSHA384() {
		
		AuthorizationCode code = new AuthorizationCode("YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL");
		
		CodeHash expectedHash = new CodeHash("adt46pcdiB-l6eTNifgoVM-5AIJAxq84");
		
		for (JWSAlgorithm jwsAlgorithm: Arrays.asList(
			JWSAlgorithm.HS384,
			JWSAlgorithm.RS384,
			JWSAlgorithm.PS384,
			JWSAlgorithm.ES384)) {
			
			assertEquals(expectedHash, CodeHash.compute(code, jwsAlgorithm));
			assertEquals(expectedHash, CodeHash.compute(code, jwsAlgorithm, null));
		}
	}
	
	
	// https://bitbucket.org/openid/connect/issues/1125/_hash-algorithm-for-eddsa-id-tokens#comment-57040192
	public void testComputeWithSHA512() {
		
		AuthorizationCode code = new AuthorizationCode("YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL");
		
		CodeHash expectedHash = new CodeHash("p2LHG4H-8pYDc0hyVOo3iIHvZJUqe9tbj3jESOuXbkY");
		
		for (JWSAlgorithm jwsAlgorithm: Arrays.asList(
			JWSAlgorithm.HS512,
			JWSAlgorithm.RS512,
			JWSAlgorithm.PS512,
			JWSAlgorithm.ES512)) {
			
			assertEquals(expectedHash, CodeHash.compute(code, jwsAlgorithm));
			assertEquals(expectedHash, CodeHash.compute(code, jwsAlgorithm, null));
		}
	}
	
	// https://bitbucket.org/openid/connect/issues/1125/_hash-algorithm-for-eddsa-id-tokens#comment-57040192
	public void testComputeWithSHA512_EdDSA() {
		
		AuthorizationCode code = new AuthorizationCode("YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL");
		
		CodeHash expectedHash = new CodeHash("p2LHG4H-8pYDc0hyVOo3iIHvZJUqe9tbj3jESOuXbkY");
		
		assertEquals(expectedHash, CodeHash.compute(code, JWSAlgorithm.EdDSA, Curve.Ed25519));
	}


	public void testEquality() {

		AuthorizationCode code = new AuthorizationCode();

		assertEquals(CodeHash.compute(code, JWSAlgorithm.HS512), CodeHash.compute(code, JWSAlgorithm.HS512));
		assertEquals(CodeHash.compute(code, JWSAlgorithm.HS512, null), CodeHash.compute(code, JWSAlgorithm.HS512, null));
	}


	public void testUnsupportedJWSAlg() {

		AuthorizationCode code = new AuthorizationCode();

		assertNull(CodeHash.compute(code, new JWSAlgorithm("no-such-alg")));
		assertNull(CodeHash.compute(code, new JWSAlgorithm("no-such-alg"), null));
	}


	public void testIDTokenRequirement()
		throws Exception {

		// code flow
		// http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
		assertFalse(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("code")));

		// implicit flow
		// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken
		assertFalse(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("id_token")));
		assertFalse(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("id_token token")));

		// hybrid flow
		// http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
		assertTrue(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("code id_token")));
		assertFalse(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("code token")));
		assertTrue(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("code id_token token")));
	}
}
