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


import java.net.URI;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import junit.framework.TestCase;
import org.joda.time.Instant;
import org.junit.Assert;


public class JARMValidatorTest extends TestCase {
	
	
	private static final RSAKey SERVER_RSA_JWK;
	
	
	private static final JWKSet SERVER_JWK_SET;
	
	
	private static final AuthorizationSuccessResponse SAMPLE_AUTHZ_RESPONSE =
		new AuthorizationSuccessResponse(
			URI.create("https://client.example.com/cb"),
			new AuthorizationCode(),
			null,
			new State(),
			ResponseMode.QUERY_JWT
		);
	
	
	static {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(2048);
			KeyPair keyPair = gen.generateKeyPair();
			SERVER_RSA_JWK = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID("1")
				.keyUse(KeyUse.SIGNATURE)
				.build();
			SERVER_JWK_SET = new JWKSet(SERVER_RSA_JWK);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testConstant() {
		
		assertEquals(60, JARMValidator.DEFAULT_MAX_CLOCK_SKEW);
	}
	
	
	public void testRejectPlain()
		throws Exception {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		
		JARMValidator jarmValidator = new JARMValidator(iss, clientID, JWSAlgorithm.RS256, new JWKSet());
		
		JWTClaimsSet claimsSet = JARMUtils.toJWTClaimsSet(
			iss,
			clientID,
			Instant.now().plus(1000L).toDate(),
			SAMPLE_AUTHZ_RESPONSE);
		
		PlainJWT jarm = new PlainJWT(claimsSet);
		
		try {
			jarmValidator.validate(jarm);
			fail();
		} catch (BadJWTException e) {
			assertEquals("The JWT must not be plain (unsecured)", e.getMessage());
		}
	}
	
	
	public void testVerifySigned()
		throws Exception {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date exp = new Date((new Date().getTime() / 1000 * 1000) + 1000);
		
		JARMValidator jarmValidator = new JARMValidator(iss, clientID, JWSAlgorithm.RS256, SERVER_JWK_SET);
		
		JWTClaimsSet claimsSet = JARMUtils.toJWTClaimsSet(
			iss,
			clientID,
			exp,
			SAMPLE_AUTHZ_RESPONSE);
		
		SignedJWT jarm = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
		jarm.sign(new RSASSASigner(SERVER_RSA_JWK));
		
		claimsSet = jarmValidator.validate(jarm);
		assertEquals(iss.getValue(), claimsSet.getIssuer());
		assertEquals(clientID.getValue(), claimsSet.getAudience().get(0));
		assertEquals(exp, claimsSet.getExpirationTime());
		assertEquals(SAMPLE_AUTHZ_RESPONSE.getState().getValue(), claimsSet.getStringClaim("state"));
		assertEquals(SAMPLE_AUTHZ_RESPONSE.getAuthorizationCode().getValue(), claimsSet.getStringClaim("code"));
	}
	
	
	public void testRejectBadSignature()
		throws Exception {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date exp = new Date((new Date().getTime() / 1000 * 1000) + 1000);
		
		JARMValidator jarmValidator = new JARMValidator(iss, clientID, JWSAlgorithm.RS256, SERVER_JWK_SET);
		
		JWTClaimsSet claimsSet = JARMUtils.toJWTClaimsSet(
			iss,
			clientID,
			exp,
			SAMPLE_AUTHZ_RESPONSE);
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair keyPair = gen.generateKeyPair();
		RSAKey invalidRSAJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
			.privateKey((RSAPrivateKey)keyPair.getPrivate())
			.keyID("1")
			.keyUse(KeyUse.SIGNATURE)
			.build();
		
		SignedJWT jarm = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
		jarm.sign(new RSASSASigner(invalidRSAJWK));
		
		try {
			jarmValidator.validate(jarm);
			fail();
		} catch (BadJWSException e) {
			assertEquals("Signed JWT rejected: Invalid signature", e.getMessage());
		}
	}
	
	
	public void testVerifyHMAC()
		throws Exception {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date exp = new Date((new Date().getTime() / 1000 * 1000) + 1000);
		
		Secret clientSecret = new Secret(ByteUtils.byteLength(256));
		
		JARMValidator jarmValidator = new JARMValidator(iss, clientID, JWSAlgorithm.HS256, clientSecret);
		
		JWTClaimsSet claimsSet = JARMUtils.toJWTClaimsSet(
			iss,
			clientID,
			exp,
			SAMPLE_AUTHZ_RESPONSE);
		
		SignedJWT jarm = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		jarm.sign(new MACSigner(clientSecret.getValueBytes()));
		
		claimsSet = jarmValidator.validate(jarm);
		assertEquals(iss.getValue(), claimsSet.getIssuer());
		assertEquals(clientID.getValue(), claimsSet.getAudience().get(0));
		assertEquals(exp, claimsSet.getExpirationTime());
		assertEquals(SAMPLE_AUTHZ_RESPONSE.getState().getValue(), claimsSet.getStringClaim("state"));
		assertEquals(SAMPLE_AUTHZ_RESPONSE.getAuthorizationCode().getValue(), claimsSet.getStringClaim("code"));
	}
	
	
	public void testRejectBadHMAC()
		throws Exception {
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date exp = new Date((new Date().getTime() / 1000 * 1000) + 1000);
		
		Secret clientSecret = new Secret(ByteUtils.byteLength(256));
		
		JARMValidator jarmValidator = new JARMValidator(iss, clientID, JWSAlgorithm.HS256, clientSecret);
		
		JWTClaimsSet claimsSet = JARMUtils.toJWTClaimsSet(
			iss,
			clientID,
			exp,
			SAMPLE_AUTHZ_RESPONSE);
		
		SignedJWT jarm = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		jarm.sign(new MACSigner(new Secret(ByteUtils.byteLength(256)).getValueBytes()));
		
		try {
			jarmValidator.validate(jarm);
			fail();
		} catch (BadJWSException e) {
			assertEquals("Signed JWT rejected: Invalid signature", e.getMessage());
		}
	}
	
	
	public void testVerifyNested()
		throws Exception {
		
		
		// Generate RP key
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair keyPair = gen.generateKeyPair();
		RSAKey rpJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
			.privateKey((RSAPrivateKey)keyPair.getPrivate())
			.keyID("e1")
			.keyUse(KeyUse.ENCRYPTION)
			.build();
		final JWKSet clientJWKSet = new JWKSet(rpJWK);
		
		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date exp = new Date((new Date().getTime() / 1000 * 1000) + 1000);
		
		JWTClaimsSet claimsSet = JARMUtils.toJWTClaimsSet(
			iss,
			clientID,
			exp,
			SAMPLE_AUTHZ_RESPONSE);
		
		SignedJWT jarm = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(SERVER_RSA_JWK.getKeyID()).build(), claimsSet);
		jarm.sign(new RSASSASigner(SERVER_RSA_JWK));
		
		JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256).keyID("e1").contentType("JWT").build(), new Payload(jarm));
		jweObject.encrypt(new RSAEncrypter(rpJWK));
		
		String jarmJWTString = jweObject.serialize();
		
		JARMValidator jarmValidator = new JARMValidator(
			iss,
			clientID,
			new JWSVerificationKeySelector(
				JWSAlgorithm.RS256,
				new ImmutableJWKSet(SERVER_JWK_SET)),
			new JWEDecryptionKeySelector(
				JWEAlgorithm.RSA_OAEP_256,
				EncryptionMethod.A128CBC_HS256,
				new ImmutableJWKSet(clientJWKSet)));
		
		assertEquals(iss, jarmValidator.getExpectedIssuer());
		assertEquals(clientID, jarmValidator.getClientID());
		assertNotNull(jarmValidator.getJWSKeySelector());
		assertNotNull(jarmValidator.getJWEKeySelector());
		
		claimsSet = jarmValidator.validate(JWTParser.parse(jarmJWTString));
		assertEquals(iss.getValue(), claimsSet.getIssuer());
		assertEquals(clientID.getValue(), claimsSet.getAudience().get(0));
		assertEquals(exp, claimsSet.getExpirationTime());
		assertEquals(SAMPLE_AUTHZ_RESPONSE.getState().getValue(), claimsSet.getStringClaim("state"));
		assertEquals(SAMPLE_AUTHZ_RESPONSE.getAuthorizationCode().getValue(), claimsSet.getStringClaim("code"));
	}
	
	
	public static Map.Entry<OIDCProviderMetadata,List<RSAKey>> createOPMetadata()
		throws Exception {
		
		// Generate 2 RSA keys for the OP
		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();
		
		final RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();
		
		keyPair = pairGen.generateKeyPair();
		
		final RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("2")
			.build();
		
		OIDCProviderMetadata opMetadata = new OIDCProviderMetadata(
			new Issuer("https://c2id.com"),
			Collections.singletonList(SubjectType.PUBLIC),
			URI.create("https://c2id.com/jwks.json"));
		
		opMetadata.setAuthorizationJWSAlgs(Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.HS256));
		opMetadata.setAuthorizationJWEAlgs(Collections.singletonList(JWEAlgorithm.RSA_OAEP_256));
		opMetadata.setAuthorizationJWEEncs(Arrays.asList(EncryptionMethod.A128CBC_HS256, EncryptionMethod.A128GCM));
		opMetadata.setTokenEndpointAuthMethods(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		opMetadata.applyDefaults();
		
		return new AbstractMap.SimpleImmutableEntry<>(opMetadata, Arrays.asList(rsaJWK1, rsaJWK2));
	}
	
	
	public void testStaticFactoryMethod_HS256()
		throws Exception {
		
		// Create OP metadata
		OIDCProviderMetadata opMetadata = createOPMetadata().getKey();
		
		// Create client registration
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(URI.create("https://example.com/cb"));
		metadata.setAuthorizationJWSAlg(JWSAlgorithm.HS256);
		metadata.applyDefaults();
		
		OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), metadata, new Secret(ByteUtils.byteLength(256)));
		
		// Create validator
		JARMValidator jarmValidator = JARMValidator.create(opMetadata, clientInfo, null);
		assertEquals(opMetadata.getIssuer(), jarmValidator.getExpectedIssuer());
		assertEquals(clientInfo.getID(), jarmValidator.getClientID());
		assertNotNull(jarmValidator.getJWSKeySelector());
		assertNull(jarmValidator.getJWEKeySelector());
		
		// Check JWS key selector
		List<Key> matches = jarmValidator.getJWSKeySelector().selectJWSKeys(new JWSHeader(JWSAlgorithm.HS256), null);
		assertEquals(1, matches.size());
		Assert.assertArrayEquals(clientInfo.getSecret().getValueBytes(), matches.get(0).getEncoded());
		
		matches = jarmValidator.getJWSKeySelector().selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("xxx").build(), null);
		assertTrue(matches.isEmpty());
		
		
		// Create JARM
		Date exp = new Date((new Date().getTime() / 1000 * 1000) + 1000);
		
		JWTClaimsSet claimsSet = JARMUtils.toJWTClaimsSet(
			opMetadata.getIssuer(),
			clientInfo.getID(),
			exp,
			SAMPLE_AUTHZ_RESPONSE);
		
		SignedJWT jarm = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		jarm.sign(new MACSigner(clientInfo.getSecret().getValueBytes()));
		
		assertEquals(1, jarmValidator.getJWSKeySelector().selectJWSKeys(jarm.getHeader(), null).size());
		
		// Validate
		claimsSet = jarmValidator.validate(jarm);
		assertEquals(opMetadata.getIssuer().getValue(), claimsSet.getIssuer());
		assertEquals(clientInfo.getID().getValue(), claimsSet.getAudience().get(0));
		assertEquals(exp, claimsSet.getExpirationTime());
		assertEquals(SAMPLE_AUTHZ_RESPONSE.getState().getValue(), claimsSet.getStringClaim("state"));
		assertEquals(SAMPLE_AUTHZ_RESPONSE.getAuthorizationCode().getValue(), claimsSet.getStringClaim("code"));
		
		// Sign ID token with invalid RSA key
		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(2048);
		KeyPair keyPair = pairGen.generateKeyPair();
		
		final RSAKey badKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();
		
		jarm = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(badKey.getKeyID()).build(), claimsSet);
		jarm.sign(new RSASSASigner(badKey));
		assertEquals(JWSObject.State.SIGNED, jarm.getState());
		
		try {
			jarmValidator.validate(jarm);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: Another algorithm expected, or no matching key(s) found", e.getMessage());
		}
		
		// Sign ID token with bad HMAC key
		jarm = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("XXXXXXX").build(), claimsSet);
		jarm.sign(new MACSigner("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
		assertEquals(JWSObject.State.SIGNED, jarm.getState());
		
		try {
			jarmValidator.validate(jarm);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: Another algorithm expected, or no matching key(s) found", e.getMessage());
		}
	}
}
