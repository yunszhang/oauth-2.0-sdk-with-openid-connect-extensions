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

package com.nimbusds.openid.connect.sdk.validators;


import java.net.URI;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;
import org.junit.Assert;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.LogoutTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;


public class LogoutTokenValidatorTest extends TestCase {
	
	
	private static Issuer ISSUER = new Issuer(URI.create("https://c2id.com"));
	
	
	private static JWTID JWTID = new JWTID();
	
	
	private static Subject SUBJECT = new Subject("alice");
	
	
	private static SessionID SESSION_ID = new SessionID(UUID.randomUUID().toString());
	
	
	private static ClientID CLIENT_ID = new ClientID("123");
	
	
	private static Secret CLIENT_SECRET = new Secret(32);
	
	
	private static final RSAKey RSA_JWK;
	
	
	static {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(2048);
			KeyPair kp = gen.generateKeyPair();
			RSA_JWK = new RSAKey.Builder((RSAPublicKey)kp.getPublic())
				.privateKey((RSAPrivateKey)kp.getPrivate())
				.keyIDFromThumbprint()
				.build();
			
		} catch (NoSuchAlgorithmException | JOSEException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testRejectPlainJWT()
		throws Exception {
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			null)
			.toJWTClaimsSet();
		
		JWT logoutToken = new PlainJWT(claimsSet);
		
		try {
			validator.validate(logoutToken);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Unsecured (plain) logout tokens are illegal", e.getMessage());
		}
	}
	
	
	public void testGoodRSASigned_sub()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			null)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.keyID(RSA_JWK.getKeyID())
				.build(),
			claimsSet);
		
		jwt.sign(new RSASSASigner(RSA_JWK));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.RS256, new JWKSet(RSA_JWK)
		);
		
		LogoutTokenClaimsSet validatedClaims = validator.validate(jwt);
		
		assertEquals(ISSUER, validatedClaims.getIssuer());
		assertEquals(SUBJECT, validatedClaims.getSubject());
		assertEquals(new Audience(CLIENT_ID).toSingleAudienceList(), validatedClaims.getAudience());
		assertNotNull(validatedClaims.getIssueTime());
		assertEquals(JWTID, validatedClaims.getJWTID());
		assertNull(validatedClaims.getSessionID());
	}
	
	
	public void testGoodRSASigned_sid()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			null,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			SESSION_ID)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.keyID(RSA_JWK.getKeyID())
				.build(),
			claimsSet);
		
		jwt.sign(new RSASSASigner(RSA_JWK));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.RS256, new JWKSet(RSA_JWK)
		);
		
		LogoutTokenClaimsSet validatedClaims = validator.validate(jwt);
		
		assertEquals(ISSUER, validatedClaims.getIssuer());
		assertNull(validatedClaims.getSubject());
		assertEquals(new Audience(CLIENT_ID).toSingleAudienceList(), validatedClaims.getAudience());
		assertNotNull(validatedClaims.getIssueTime());
		assertEquals(JWTID, validatedClaims.getJWTID());
		assertEquals(SESSION_ID, validatedClaims.getSessionID());
	}
	
	
	public void testGoodRSASigned_sub_sid()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			SESSION_ID)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.keyID(RSA_JWK.getKeyID())
				.build(),
			claimsSet);
		
		jwt.sign(new RSASSASigner(RSA_JWK));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.RS256, new JWKSet(RSA_JWK)
		);
		
		LogoutTokenClaimsSet validatedClaims = validator.validate(jwt);
		
		assertEquals(ISSUER, validatedClaims.getIssuer());
		assertEquals(SUBJECT, validatedClaims.getSubject());
		assertEquals(new Audience(CLIENT_ID).toSingleAudienceList(), validatedClaims.getAudience());
		assertNotNull(validatedClaims.getIssueTime());
		assertEquals(JWTID, validatedClaims.getJWTID());
		assertEquals(SESSION_ID, validatedClaims.getSessionID());
	}
	
	
	public void testGoodHMACSecured()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			null)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			claimsSet);
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		LogoutTokenClaimsSet validatedClaims = validator.validate(jwt);
		
		assertEquals(ISSUER, validatedClaims.getIssuer());
		assertEquals(SUBJECT, validatedClaims.getSubject());
		assertEquals(new Audience(CLIENT_ID).toSingleAudienceList(), validatedClaims.getAudience());
		assertNotNull(validatedClaims.getIssueTime());
		assertEquals(JWTID, validatedClaims.getJWTID());
		assertNull(validatedClaims.getSessionID());
	}
	
	
	public void testHMACSecured_badHmac()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			null)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			claimsSet);
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, new Secret() // other hmac
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWSException e) {
			assertEquals("Signed JWT rejected: Invalid signature", e.getMessage());
		}
	}
	
	
	public void testNonceIllegal()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			null)
			.toJWTClaimsSet();
		
		claimsSet = new JWTClaimsSet.Builder(claimsSet)
			.claim("nonce", "abc")
			.build();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			claimsSet);
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Found illegal nonce (nonce) claim", e.getMessage());
		}
	}
	
	
	public void testMissing_sub_sid()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			null)
			.toJWTClaimsSet();
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		jsonObject.remove("sub");
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing subject (sub) and / or session ID (sid) claim(s)", e.getMessage());
		}
	}
	
	
	public void testMissingEvents()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			null)
			.toJWTClaimsSet();
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		jsonObject.remove("events");
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT events (events) claim", e.getMessage());
		}
	}
	
	
	public void testMissingEventsType()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			null)
			.toJWTClaimsSet();
		
		JSONObject jsonObject = JSONObjectUtils.toJSONObject(claimsSet);
		JSONObject events = (JSONObject)jsonObject.get("events");
		events.remove(LogoutTokenClaimsSet.EVENT_TYPE);
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing event type, required http://schemas.openid.net/event/backchannel-logout", e.getMessage());
		}
	}
	
	
	public void testMissingIssuer()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			null)
			.toJWTClaimsSet();
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		jsonObject.remove("iss");
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT issuer (iss) claim", e.getMessage());
		}
	}
	
	
	public void testUnexpectedIssuer()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			new Issuer(URI.create("https://other-idp.com")),
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			null)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			claimsSet);
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Unexpected JWT issuer: https://other-idp.com", e.getMessage());
		}
	}
	
	
	public void testMissingAudience()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			null)
			.toJWTClaimsSet();
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		jsonObject.remove("aud");
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT audience (aud) claim", e.getMessage());
		}
	}
	
	
	public void testUnexpectedAudience()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(new ClientID("other-client-id")).toSingleAudienceList(),
			new Date(),
			JWTID,
			null)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			claimsSet);
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Unexpected JWT audience: [other-client-id]", e.getMessage());
		}
	}
	
	
	public void testMissingJTI()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			null)
			.toJWTClaimsSet();
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		jsonObject.remove("jti");
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT ID (jti) claim", e.getMessage());
		}
	}
	
	
	public void testMissingIssueTime()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			new Date(),
			JWTID,
			null)
			.toJWTClaimsSet();
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		jsonObject.remove("iat");
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT issue time (iat) claim", e.getMessage());
		}
	}
	
	
	public void testStaticFactoryMethod_HS256()
		throws Exception {
		
		// Create OP metadata (based on ID_token algs)
		OIDCProviderMetadata opMetadata = IDTokenValidatorTest.createOPMetadata().getKey();
		
		// Create client registration
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(URI.create("https://example.com/cb"));
		metadata.setIDTokenJWSAlg(JWSAlgorithm.HS256);
		metadata.applyDefaults();
		
		OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), metadata, new Secret(ByteUtils.byteLength(256)));
		
		// Create validator
		LogoutTokenValidator v = LogoutTokenValidator.create(opMetadata, clientInfo, null);
		assertEquals(opMetadata.getIssuer(), v.getExpectedIssuer());
		assertEquals(clientInfo.getID(), v.getClientID());
		assertNotNull(v.getJWSKeySelector());
		assertNull(v.getJWEKeySelector());
		
		// Check JWS key selector
		List<Key> matches = v.getJWSKeySelector().selectJWSKeys(new JWSHeader(JWSAlgorithm.HS256), null);
		assertEquals(1, matches.size());
		Assert.assertArrayEquals(clientInfo.getSecret().getValueBytes(), matches.get(0).getEncoded());
		
		matches = v.getJWSKeySelector().selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("xxx").build(), null);
		assertTrue(matches.isEmpty());
		
		
		// Create ID token
		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 3600*1000L);
		LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(clientInfo.getID()).toSingleAudienceList(),
			now,
			JWTID,
			SESSION_ID);
		
		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());
		idToken.sign(new MACSigner(clientInfo.getSecret().getValueBytes()));
		idToken = SignedJWT.parse(idToken.serialize());
		
		assertEquals(1, v.getJWSKeySelector().selectJWSKeys(idToken.getHeader(), null).size());
		
		// Validate
		LogoutTokenClaimsSet validated = v.validate(idToken);
		assertEquals(claimsSet.getIssuer(), validated.getIssuer());
		assertEquals(claimsSet.getSubject(), validated.getSubject());
		assertEquals(claimsSet.getAudience().get(0), validated.getAudience().get(0));
		assertEquals(1, validated.getAudience().size());
		assertEquals(claimsSet.getIssueTime(), validated.getIssueTime());
		
		// Sign logout token with invalid RSA key
		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(2048);
		KeyPair keyPair = pairGen.generateKeyPair();
		
		final RSAKey badKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();
		
		idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(badKey.getKeyID()).build(), claimsSet.toJWTClaimsSet());
		idToken.sign(new RSASSASigner(badKey));
		assertEquals(JWSObject.State.SIGNED, idToken.getState());
		
		try {
			v.validate(idToken);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: Another algorithm expected, or no matching key(s) found", e.getMessage());
		}
		
		// Sign ID token with bad HMAC key
		idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("XXXXXXX").build(), claimsSet.toJWTClaimsSet());
		idToken.sign(new MACSigner("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
		assertEquals(JWSObject.State.SIGNED, idToken.getState());
		
		try {
			v.validate(idToken);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: Another algorithm expected, or no matching key(s) found", e.getMessage());
		}
	}
}
