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


import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


public class EntityStatementTest extends TestCase {
	
	
	private static final RSAKey RSA_JWK;
	
	
	private static final JWKSet SIMPLE_JWK_SET;
	
	
	private static final OIDCProviderMetadata OP_METADATA;
	
	
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
		
		OP_METADATA = new OIDCProviderMetadata(
			new Issuer("https://op.c2id.com"),
			Collections.singletonList(SubjectType.PAIRWISE),
			URI.create("https://op.c2id.com/jwks.json"));
		OP_METADATA.setAuthorizationEndpointURI(URI.create("https://op.c2id.com/login"));
		OP_METADATA.setTokenEndpointURI(URI.create("https://op.c2id.com/token"));
		OP_METADATA.applyDefaults();
	}
	
	
	private static EntityStatementClaimsSet createEntityStatementClaimsSet() {
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date iat = DateUtils.fromSecondsSinceEpoch(nowTS);
		Date exp = DateUtils.fromSecondsSinceEpoch(nowTS + 60);
		
		Issuer iss = OP_METADATA.getIssuer();
		Subject sub = new Subject(OP_METADATA.getIssuer().getValue());
		List<EntityID> authorityHints = Collections.singletonList(new EntityID("https://federation.example.com"));
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			SIMPLE_JWK_SET);
		stmt.setOPMetadata(OP_METADATA);
		stmt.setAuthorityHints(authorityHints);
		return stmt;
	}
	

	public void testLifecycle_defaultJWSAlg() throws Exception {
		
		EntityStatementClaimsSet claimsSet = createEntityStatementClaimsSet();
		
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, RSA_JWK);
		
		assertEquals(OP_METADATA.getIssuer().getValue(), entityStatement.getEntityID().getValue());
		assertEquals(claimsSet.toJWTClaimsSet().getClaims(), entityStatement.getClaimsSet().toJWTClaimsSet().getClaims());
		assertFalse(entityStatement.isTrustAnchor());
		
		JWSHeader jwsHeader = entityStatement.getSignedStatement().getHeader();
		assertEquals(JWSAlgorithm.RS256, jwsHeader.getAlgorithm());
		assertEquals(RSA_JWK.getKeyID(), jwsHeader.getKeyID());
		assertEquals(2,  jwsHeader.toJSONObject().size());
		
		SignedJWT signedJWT = entityStatement.getSignedStatement();
		assertEquals(claimsSet.toJWTClaimsSet().getClaims(), signedJWT.getJWTClaimsSet().getClaims());
		assertTrue(signedJWT.verify(new RSASSAVerifier(RSA_JWK.toRSAPublicKey())));
		
		entityStatement = EntityStatement.parse(signedJWT);
		
		assertEquals(OP_METADATA.getIssuer().getValue(), entityStatement.getEntityID().getValue());
		assertEquals(claimsSet.toJWTClaimsSet().getClaims(), entityStatement.getClaimsSet().toJWTClaimsSet().getClaims());
		
		entityStatement.verifySignatureOfSelfStatement();
		entityStatement.verifySignature(SIMPLE_JWK_SET);
	}
	

	public void testLifecycle_explicitJWSAlg() throws Exception {
		
		EntityStatementClaimsSet claimsSet = createEntityStatementClaimsSet();
		
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, RSA_JWK, JWSAlgorithm.RS512);
		
		assertEquals(OP_METADATA.getIssuer().getValue(), entityStatement.getEntityID().getValue());
		assertEquals(claimsSet.toJWTClaimsSet().getClaims(), entityStatement.getClaimsSet().toJWTClaimsSet().getClaims());
		
		JWSHeader jwsHeader = entityStatement.getSignedStatement().getHeader();
		assertEquals(JWSAlgorithm.RS512, jwsHeader.getAlgorithm());
		assertEquals(RSA_JWK.getKeyID(), jwsHeader.getKeyID());
		assertEquals(2,  jwsHeader.toJSONObject().size());
		
		SignedJWT signedJWT = entityStatement.getSignedStatement();
		assertEquals(claimsSet.toJWTClaimsSet().getClaims(), signedJWT.getJWTClaimsSet().getClaims());
		assertTrue(signedJWT.verify(new RSASSAVerifier(RSA_JWK.toRSAPublicKey())));
		
		entityStatement = EntityStatement.parse(signedJWT);
		
		assertEquals(OP_METADATA.getIssuer().getValue(), entityStatement.getEntityID().getValue());
		assertEquals(claimsSet.toJWTClaimsSet().getClaims(), entityStatement.getClaimsSet().toJWTClaimsSet().getClaims());
		
		entityStatement.verifySignatureOfSelfStatement();
		entityStatement.verifySignature(SIMPLE_JWK_SET);
	}
	
	
	public void testExpired() throws Exception {
		
		EntityStatementClaimsSet claimsSet = createEntityStatementClaimsSet();
		
		// Put exp in past
		long now = DateUtils.toSecondsSinceEpoch(new Date());
		long iat = now - 3600;
		long exp = now - 1800;
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder(claimsSet.toJWTClaimsSet())
			.issueTime(DateUtils.fromSecondsSinceEpoch(iat))
			.expirationTime(DateUtils.fromSecondsSinceEpoch(exp))
			.build();
		
		claimsSet = new EntityStatementClaimsSet(jwtClaimsSet);
		
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, RSA_JWK);
		
		try {
			EntityStatement.parse(entityStatement.getSignedStatement()).verifySignatureOfSelfStatement();
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}
	
	
	public void testInvalidSignature_noMatchingKey() throws Exception {
		
		EntityStatementClaimsSet claimsSet = createEntityStatementClaimsSet();
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyIDFromThumbprint(true)
			.generate();
		
		SignedJWT signedJWT = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
			claimsSet.toJWTClaimsSet()
		);
		signedJWT.sign(new RSASSASigner(rsaJWK));
		
		try {
			EntityStatement.parse(signedJWT).verifySignatureOfSelfStatement();
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: Another algorithm expected, or no matching key(s) found", e.getMessage());
		}
	}
	
	
	public void testInvalidSignature_signature() throws Exception {
		
		EntityStatementClaimsSet claimsSet = createEntityStatementClaimsSet();
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyID(RSA_JWK.getKeyID())
			.generate();
		
		SignedJWT signedJWT = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
			claimsSet.toJWTClaimsSet()
		);
		signedJWT.sign(new RSASSASigner(rsaJWK));
		
		try {
			EntityStatement.parse(signedJWT).verifySignatureOfSelfStatement();
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: Invalid signature", e.getMessage());
		}
	}
	
	
	public void testIsForTrustAnchor() throws Exception {
		
		EntityStatementClaimsSet claimsSet = createEntityStatementClaimsSet();
		claimsSet.setAuthorityHints(null);
		
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, RSA_JWK);
		
		assertTrue(entityStatement.isTrustAnchor());
	}
}
