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

package com.nimbusds.oauth2.sdk.dpop.verifiers;


import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;


public class DPoPCommonVerifierTest extends TestCase {


	public void testSupportedJWSAlgorithms() {
		
		Set<JWSAlgorithm> jwsAlgorithms = new HashSet<>();
		jwsAlgorithms.addAll(JWSAlgorithm.Family.RSA);
		jwsAlgorithms.addAll(JWSAlgorithm.Family.EC);
		
		assertEquals(jwsAlgorithms, DPoPCommonVerifier.SUPPORTED_JWS_ALGORITHMS);
		
		new DPoPCommonVerifier(
			jwsAlgorithms,
			"POST",
			URI.create("https://c2id.com/token"),
			2,
			false,
			new DefaultDPoPSingleUseChecker(
				10,
				10
			)
		);
	}
	
	
	public void testForTokenEndpoint_ES256() throws Exception {
		
		String htm = "POST";
		URI htu = URI.create("https://c2id.com/token");
		
		DPoPIssuer issuer = new DPoPIssuer("client-123");
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256).generate();
		DPoPProofFactory dPoPProofFactory = new DefaultDPoPProofFactory(
			ecJWK,
			JWSAlgorithm.ES256
		);
		
		DPoPCommonVerifier verifier = new DPoPCommonVerifier(
			Collections.singleton(JWSAlgorithm.ES256),
			htm,
			htu,
			2,
			false,
			new DefaultDPoPSingleUseChecker(
				10,
				10
			)
		);
		
		SignedJWT proof = dPoPProofFactory.createDPoPJWT(htm, htu);
		
		verifier.verify(issuer, proof, null, null);
		
		// Replay detection
		try {
			verifier.verify(issuer, proof, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: The jti was used before: " + proof.getJWTClaimsSet().getJWTID(), e.getMessage());
		}
		
		// Invalid HTTP method
		proof = dPoPProofFactory.createDPoPJWT("PUT", htu);
		
		try {
			verifier.verify(issuer, proof, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWT \"htm\" claim has value PUT, must be POST", e.getMessage());
		}
		
		// Invalid HTTP URL
		proof = dPoPProofFactory.createDPoPJWT(htm, URI.create("https://op.example.com/userinfo"));
		
		try {
			verifier.verify(issuer, proof, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWT \"htu\" claim has value https://op.example.com/userinfo, must be https://c2id.com/token", e.getMessage());
		}
		
		// JWS alg not accepted
		proof = new DefaultDPoPProofFactory(
				new RSAKeyGenerator(2048).generate(),
				JWSAlgorithm.RS256
			).createDPoPJWT(htm, htu);
		
		try {
			verifier.verify(issuer, proof, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWS header algorithm not accepted: RS256", e.getMessage());
		}
		
		// Missing typ header
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
			.jwtID(new JWTID().getValue())
			.claim("htm", htm)
			.claim("htu", htu.toString())
			.issueTime(new Date())
			.build();
		proof = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.ES256).jwk(ecJWK.toPublicJWK()).build(),
			jwtClaimsSet
		);
		proof.sign(new ECDSASigner(ecJWK));
		
		try {
			verifier.verify(issuer, proof, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: Required JOSE header \"typ\" (type) parameter is missing", e.getMessage());
		}
		
		// Missing jwk header
		proof = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.ES256).type(DPoPProofFactory.TYPE).build(),
			jwtClaimsSet
		);
		proof.sign(new ECDSASigner(ecJWK));
		
		try {
			verifier.verify(issuer, proof, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: Missing JWS jwk header parameter", e.getMessage());
		}
		
		// Signing key doesn't match jwk header
		proof = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.ES256)
				.type(DPoPProofFactory.TYPE)
				.jwk(new ECKeyGenerator(Curve.P_256).generate().toPublicJWK())
				.build(),
			jwtClaimsSet
		);
		proof.sign(new ECDSASigner(ecJWK));
		
		try {
			verifier.verify(issuer, proof, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: Signed JWT rejected: Invalid signature", e.getMessage());
		}
		
		// jwk in header other key type
		proof = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.ES256)
				.type(DPoPProofFactory.TYPE)
				.jwk(new RSAKeyGenerator(2048).generate().toPublicJWK())
				.build(),
			jwtClaimsSet
		);
		proof.sign(new ECDSASigner(ecJWK));
		
		try {
			verifier.verify(issuer, proof, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWS header alg / jwk mismatch: alg=ES256 jwk.kty=RSA", e.getMessage());
		}
	}
	
	
	public void testForProtectedResource() throws Exception {
		
		String htm = "POST";
		URI htu = URI.create("https://c2id.com/userinfo");
		
		DPoPAccessToken accessToken = new DPoPAccessToken("iat5luciwooSa8Ogh5eweicahG8soo8a");
		
		DPoPIssuer issuer = new DPoPIssuer("client-123");
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256).generate();
		Base64URL jkt = ecJWK.computeThumbprint();
		JWKThumbprintConfirmation cnf = new JWKThumbprintConfirmation(jkt);
		DPoPProofFactory dPoPProofFactory = new DefaultDPoPProofFactory(
			ecJWK,
			JWSAlgorithm.ES256
		);
		
		DPoPCommonVerifier verifier = new DPoPCommonVerifier(
			Collections.singleton(JWSAlgorithm.ES256),
			htm,
			htu,
			2,
			true,
			new DefaultDPoPSingleUseChecker(
				10,
				10
			)
		);
		
		// Pass
		SignedJWT proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken);
		assertNotNull(proof.getJWTClaimsSet().getStringClaim("ath"));
		
		verifier.verify(issuer, proof, accessToken, cnf);
		
		// Replay detection
		try {
			verifier.verify(issuer, proof, accessToken, cnf);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: The jti was used before: " + proof.getJWTClaimsSet().getJWTID(), e.getMessage());
		}
		
		// Missing access token
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken);
		try {
			verifier.verify(issuer, proof, null, cnf);
			fail();
		} catch (AccessTokenValidationException e) {
			assertEquals("Missing access token", e.getMessage());
		}
		
		// Missing cnf
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken);
		try {
			verifier.verify(issuer, proof, accessToken, null);
			fail();
		} catch (AccessTokenValidationException e) {
			assertEquals("Missing JWK SHA-256 thumbprint confirmation", e.getMessage());
		}
		
		// Missing ath
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, null);
		try {
			verifier.verify(issuer, proof, accessToken, cnf);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWT missing required claims: [ath]", e.getMessage());
		}
		
		// Invalid ath - access token binding
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, new DPoPAccessToken("other-value"));
		
		try {
			verifier.verify(issuer, proof, accessToken, cnf);
			fail();
		} catch (AccessTokenValidationException e) {
			assertEquals("The access token hash doesn't match the JWT ath claim", e.getMessage());
		}
		
		// Invalid cnf - access token binding
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken);
		
		JWKThumbprintConfirmation invalidCNF = new JWKThumbprintConfirmation(new ECKeyGenerator(Curve.P_256).generate().computeThumbprint());
		
		try {
			verifier.verify(issuer, proof, accessToken, invalidCNF);
			fail();
		} catch (AccessTokenValidationException e) {
			assertEquals("The DPoP proof JWK doesn't match the JWK SHA-256 thumbprint confirmation", e.getMessage());
		}
	}
	
	
	public void testWithoutSingleUseChecker() throws Exception {
		
		String htm = "POST";
		URI htu = URI.create("https://c2id.com/token");
		
		DPoPIssuer issuer = new DPoPIssuer("client-123");
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256).generate();
		DPoPProofFactory dPoPProofFactory = new DefaultDPoPProofFactory(
			ecJWK,
			JWSAlgorithm.ES256
		);
		
		DPoPCommonVerifier verifier = new DPoPCommonVerifier(
			Collections.singleton(JWSAlgorithm.ES256),
			htm,
			htu,
			2,
			false,
			null
		);
		
		SignedJWT proof = dPoPProofFactory.createDPoPJWT(htm, htu);
		
		// Replay not detected
		verifier.verify(issuer, proof, null, null);
		verifier.verify(issuer, proof, null, null);
	}
}
