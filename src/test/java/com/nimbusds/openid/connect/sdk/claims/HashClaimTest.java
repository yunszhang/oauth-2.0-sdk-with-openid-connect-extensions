/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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


import java.security.MessageDigest;
import java.util.Arrays;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;


public class HashClaimTest extends TestCase {


	public void testGetMessageDigestInstance_SHA_256() {
		
		for (JWSAlgorithm jwsAlgorithm: Arrays.asList(
			JWSAlgorithm.HS256,
			JWSAlgorithm.RS256,
			JWSAlgorithm.PS256,
			JWSAlgorithm.ES256,
			JWSAlgorithm.ES256K)) {
			
			MessageDigest md = HashClaim.getMessageDigestInstance(jwsAlgorithm);
			
			assertEquals("SHA-256", md.getAlgorithm());
		}
	}


	public void testGetMessageDigestInstance_SHA_384() {
		
		for (JWSAlgorithm jwsAlgorithm: Arrays.asList(
			JWSAlgorithm.HS384,
			JWSAlgorithm.RS384,
			JWSAlgorithm.PS384,
			JWSAlgorithm.ES384)) {
			
			MessageDigest md = HashClaim.getMessageDigestInstance(jwsAlgorithm);
			
			assertEquals("SHA-384", md.getAlgorithm());
		}
	}


	public void testGetMessageDigestInstance_SHA_512() {
		
		for (JWSAlgorithm jwsAlgorithm: Arrays.asList(
			JWSAlgorithm.HS512,
			JWSAlgorithm.RS512,
			JWSAlgorithm.PS512,
			JWSAlgorithm.ES512)) {
			
			MessageDigest md = HashClaim.getMessageDigestInstance(jwsAlgorithm);
			
			assertEquals("SHA-512", md.getAlgorithm());
		}
	}
}
