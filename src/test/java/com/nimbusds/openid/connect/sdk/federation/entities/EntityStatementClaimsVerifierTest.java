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
import java.util.Date;
import java.util.HashSet;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.Audience;


public class EntityStatementClaimsVerifierTest extends TestCase {
	
	
	private static final RSAKey RSA_JWK;
	
	
	private static final JWKSet SIMPLE_JWK_SET;
	
	
	static {
		try {
			RSA_JWK = new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.keyUse(KeyUse.SIGNATURE)
				.generate();
			SIMPLE_JWK_SET = new JWKSet(RSA_JWK.toPublicJWK());
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testForSelfIssued() throws BadJWTException {
		
		EntityStatementClaimsVerifier verifier = new EntityStatementClaimsVerifier();
		assertNull(verifier.getAcceptedAudienceValues());
		assertEquals(new HashSet<>(Arrays.asList("iss", "sub", "iat", "exp", "jwks")), verifier.getRequiredClaims());
		assertTrue(verifier.getProhibitedClaims().isEmpty());
		assertTrue(verifier.getExactMatchClaims().getClaims().isEmpty());
		
		// pass
		long nowTs = new Date().getTime() / 1000;
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
			.issuer("https://op.c2id.com")
			.subject("https://op.c2id.com")
			.issueTime(DateUtils.fromSecondsSinceEpoch(nowTs - 3600))
			.expirationTime(DateUtils.fromSecondsSinceEpoch(nowTs + 3600))
			.claim("jwks", SIMPLE_JWK_SET.toJSONObject())
			.build();
		
		new EntityStatementClaimsVerifier().verify(jwtClaimsSet, null);
		
		// fail due to not-self issued
		jwtClaimsSet = new JWTClaimsSet.Builder()
			.issuer("https://op.c2id.com")
			.subject("https://client.c2id.com")
			.issueTime(DateUtils.fromSecondsSinceEpoch(nowTs - 3600))
			.expirationTime(DateUtils.fromSecondsSinceEpoch(nowTs + 3600))
			.claim("jwks", SIMPLE_JWK_SET.toJSONObject())
			.build();
		
		try {
			new EntityStatementClaimsVerifier().verify(jwtClaimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT not self-issued", e.getMessage());
		}
		
		// fail due to expired
		jwtClaimsSet = new JWTClaimsSet.Builder()
			.issuer("https://op.c2id.com")
			.subject("https://op.c2id.com")
			.issueTime(DateUtils.fromSecondsSinceEpoch(nowTs - 3600))
			.expirationTime(DateUtils.fromSecondsSinceEpoch(nowTs - 1800))
			.claim("jwks", SIMPLE_JWK_SET.toJSONObject())
			.build();
		
		try {
			new EntityStatementClaimsVerifier().verify(jwtClaimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
		
		// fail due to iat in future
		jwtClaimsSet = new JWTClaimsSet.Builder()
			.issuer("https://op.c2id.com")
			.subject("https://op.c2id.com")
			.issueTime(DateUtils.fromSecondsSinceEpoch(nowTs + 1800))
			.expirationTime(DateUtils.fromSecondsSinceEpoch(nowTs + 3600))
			.claim("jwks", SIMPLE_JWK_SET.toJSONObject())
			.build();
		
		try {
			new EntityStatementClaimsVerifier().verify(jwtClaimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT issue time after current time", e.getMessage());
		}
	}
	
	
	public void testWithExpectedAudience() {
		
		EntityStatementClaimsVerifier verifier = new EntityStatementClaimsVerifier(new Audience("https://c2id.com"));
		assertEquals(Collections.singleton("https://c2id.com"), verifier.getAcceptedAudienceValues());
		assertEquals(new HashSet<>(Arrays.asList("aud", "iss", "sub", "iat", "exp")), verifier.getRequiredClaims());
		assertTrue(verifier.getProhibitedClaims().isEmpty());
		assertTrue(verifier.getExactMatchClaims().getClaims().isEmpty());
	}
}
