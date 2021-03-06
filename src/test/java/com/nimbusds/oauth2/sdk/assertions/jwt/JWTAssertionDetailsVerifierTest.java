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

package com.nimbusds.oauth2.sdk.assertions.jwt;


import java.net.URI;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;

import junit.framework.TestCase;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;


public class JWTAssertionDetailsVerifierTest extends TestCase {
	
	
	public void testRun()
		throws Exception {
		
		Issuer issuer = new Issuer("https://c2id.com");
		URI tokenEndpoint = URI.create("https://c2id.com/token");
		
		JWTAssertionDetailsVerifier verifier = new JWTAssertionDetailsVerifier(
			new HashSet<>(Arrays.asList(
				new Audience(issuer),
				new Audience(tokenEndpoint)
			))
		);
		
		assertTrue(verifier.getExpectedAudience().contains(new Audience(issuer)));
		assertTrue(verifier.getExpectedAudience().contains(new Audience(tokenEndpoint)));
		assertEquals(2, verifier.getExpectedAudience().size());
		
		// good claims - aud = OP / AS issuer
		verifier.verify(
			new JWTClaimsSet.Builder()
				.issuer("123")
				.subject("alice")
				.audience(issuer.getValue())
				.expirationTime(new Date(new Date().getTime() + 60*1000L))
				.build(),
			null);
		
		// good claims - aud = token endpoint
		verifier.verify(
			new JWTClaimsSet.Builder()
				.issuer("123")
				.subject("alice")
				.audience(tokenEndpoint.toString())
				.expirationTime(new Date(new Date().getTime() + 60*1000L))
				.build(),
			null);
		
		// empty claims
		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT expiration claim", e.getMessage());
		}
		
		try {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.expirationTime(new Date(new Date().getTime() + 60*1000L))
					.build(),
				null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT audience claim", e.getMessage());
		}
		
		try {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.expirationTime(new Date(new Date().getTime() + 60*1000L))
					.audience(issuer.getValue())
					.build(),
				null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT issuer claim", e.getMessage());
		}
		
		try {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.expirationTime(new Date(new Date().getTime() + 60*1000L))
					.audience(issuer.getValue())
					.issuer("123")
					.build(),
				null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT subject claim", e.getMessage());
		}
		
		try {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.expirationTime(new Date(new Date().getTime() + 60*1000L))
					.audience(issuer.getValue())
					.issuer("123")
					.build(),
				null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT subject claim", e.getMessage());
		}
		
		try {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.expirationTime(new Date(new Date().getTime() - 60*1000L))
					.audience(issuer.getValue())
					.issuer("123")
					.build(),
				null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
		
		try {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.expirationTime(new Date(new Date().getTime() + 60*1000L))
					.audience("bad-audience")
					.issuer("123")
					.build(),
				null);
			fail();
		} catch (BadJWTException e) {
			assertTrue(e.getMessage().startsWith("Invalid JWT audience claim, expected"));
		}
	}
}
