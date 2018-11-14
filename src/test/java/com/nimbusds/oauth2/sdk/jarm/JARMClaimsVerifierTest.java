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

package com.nimbusds.oauth2.sdk.jarm;


import java.util.Arrays;
import java.util.Date;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import junit.framework.TestCase;


public class JARMClaimsVerifierTest extends TestCase {
	
	public void testHappyMinimal()
		throws BadJWTException {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		
		JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);
		
		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		
		Date now = new Date();
		Date exp = new Date(now.getTime() + 5*60*1000);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.audience(clientID.getValue())
			.expirationTime(exp)
			.build();
		
		verifier.verify(claimsSet, null);
	}
	
	
	public void testMissingIssuer() {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		
		JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);
		
		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		
		Date now = new Date();
		Date exp = new Date(now.getTime() + 5*60*1000);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.audience(clientID.getValue())
			.expirationTime(exp)
			.build();
		
		try {
			verifier.verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT issuer (iss) claim", e.getMessage());
		}
	}
	
	
	public void testMissingAudience() {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		
		JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);
		
		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		
		Date now = new Date();
		Date exp = new Date(now.getTime() + 5*60*1000);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.expirationTime(exp)
			.build();
		
		try {
			verifier.verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT audience (aud) claim", e.getMessage());
		}
	}
	
	
	public void testMissingExpirationTime() {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		
		JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);
		
		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.audience(clientID.getValue())
			.build();
		
		try {
			verifier.verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT expiration (exp) claim", e.getMessage());
		}
	}
	
	
	public void testUnexpectedIssuer() {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		
		JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);
		
		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		
		Date now = new Date();
		Date exp = new Date(now.getTime() + 5*60*1000);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("https://other-issuer.com")
			.audience(clientID.getValue())
			.expirationTime(exp)
			.build();
		
		try {
			verifier.verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Unexpected JWT issuer: https://other-issuer.com", e.getMessage());
		}
	}
	
	
	public void testAudienceMismatch() {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		
		JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);
		
		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		
		Date now = new Date();
		Date exp = new Date(now.getTime() + 5*60*1000);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.audience("789")
			.expirationTime(exp)
			.build();
		
		try {
			verifier.verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Unexpected JWT audience: [789]", e.getMessage());
		}
	}
	
	
	public void testMultipleAudienceMismatch() {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		
		JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);
		
		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		
		Date now = new Date();
		Date exp = new Date(now.getTime() + 5*60*1000);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.audience(Arrays.asList("456", "789"))
			.expirationTime(exp)
			.build();
		
		try {
			verifier.verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Unexpected JWT audience: [456, 789]", e.getMessage());
		}
	}
	
	
	public void testExpired() {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		
		JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);
		
		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		
		Date now = new Date();
		Date exp = new Date(now.getTime() + 5*60*1000);
		final Date oneHourAgo = new Date(now.getTime() - 60*60*1000L);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.audience(clientID.getValue())
			.expirationTime(oneHourAgo)
			.build();
		
		try {
			verifier.verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}
	
	
	public void testIssuedAtWithPositiveClockSkew()
		throws BadJWTException {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		
		JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 60);
		
		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		
		final Date now = new Date();
		final Date in30Seconds = new Date(now.getTime() + 30*1000L);
		final Date inOneHour = new Date(now.getTime() + 60*60*1000L);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.audience(clientID.getValue())
			.expirationTime(inOneHour)
			.issueTime(in30Seconds)
			.build();
		
		verifier.verify(claimsSet, null);
	}
	
	
	public void testExpirationWithNegativeClockSkew()
		throws BadJWTException {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		
		JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 60);
		
		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		
		final Date now = new Date();
		final Date oneHourAgo = new Date(now.getTime() - 60*60*1000L);
		final Date before30Seconds = new Date(now.getTime() - 30*1000L);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.audience(clientID.getValue())
			.expirationTime(before30Seconds)
			.issueTime(oneHourAgo)
			.build();
		
		verifier.verify(claimsSet, null);
	}
}
