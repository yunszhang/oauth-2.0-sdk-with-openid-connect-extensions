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

package com.nimbusds.openid.connect.sdk.federation.entities;


import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.id.Audience;


public class EntityStatementClaimsVerifierTest extends TestCase {
	
	
	public void testNoExpectedAudience() {
		
		EntityStatementClaimsVerifier verifier = new EntityStatementClaimsVerifier(null);
		assertNull(verifier.getAcceptedAudienceValues());
		assertEquals(new HashSet<>(Arrays.asList("iss", "sub", "iat", "exp", "jwks")), verifier.getRequiredClaims());
		assertTrue(verifier.getProhibitedClaims().isEmpty());
		assertTrue(verifier.getExactMatchClaims().getClaims().isEmpty());
	}
	
	
	public void testWithExpectedAudience() {
		
		EntityStatementClaimsVerifier verifier = new EntityStatementClaimsVerifier(new Audience("https://c2id.com"));
		assertEquals(Collections.singleton("https://c2id.com"), verifier.getAcceptedAudienceValues());
		assertEquals(new HashSet<>(Arrays.asList("aud", "iss", "sub", "iat", "exp", "jwks")), verifier.getRequiredClaims());
		assertTrue(verifier.getProhibitedClaims().isEmpty());
		assertTrue(verifier.getExactMatchClaims().getClaims().isEmpty());
	}
}
