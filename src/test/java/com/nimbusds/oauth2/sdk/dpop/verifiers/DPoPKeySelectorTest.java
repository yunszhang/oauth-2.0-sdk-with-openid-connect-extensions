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


import java.security.Key;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.id.ClientID;


public class DPoPKeySelectorTest extends TestCase {
	
	
	private static final DPoPIssuer ISSUER = new DPoPIssuer(new ClientID("123"));


	public void testWithRSA() throws JOSEException {
		
		RSAKey jwk = new RSAKeyGenerator(2048).generate();
		
		for (JWSAlgorithm alg: JWSAlgorithm.Family.RSA) {
			
			JWSHeader header = new JWSHeader.Builder(alg)
				.type(DPoPProofFactory.TYPE)
				.jwk(jwk.toPublicJWK())
				.build();
			
			List<Key> candidates = new DPoPKeySelector(Collections.singleton(alg))
				.selectJWSKeys(header, new DPoPProofContext(ISSUER));
			
			assertEquals(1, candidates.size());
			
			assertArrayEquals(jwk.toRSAPublicKey().getEncoded(), candidates.get(0).getEncoded());
		}
	}


	public void testWithEC() throws JOSEException {
		
		for (JWSAlgorithm alg: JWSAlgorithm.Family.EC) {
			
			if (JWSAlgorithm.ES256K.equals(alg)) {
				continue; // skip
			}
			
			ECKey jwk = new ECKeyGenerator(Curve.forJWSAlgorithm(alg).iterator().next()).generate();
			
			JWSHeader header = new JWSHeader.Builder(alg)
				.type(DPoPProofFactory.TYPE)
				.jwk(jwk.toPublicJWK())
				.build();
			
			List<Key> candidates = new DPoPKeySelector(Collections.singleton(alg))
				.selectJWSKeys(header, new DPoPProofContext(ISSUER));
			
			assertEquals(1, candidates.size());
			
			assertArrayEquals(jwk.toECPublicKey().getEncoded(), candidates.get(0).getEncoded());
		}
	}
	
	
	public void testConstructor_emptyAcceptable() {
		
		try {
			new DPoPKeySelector(Collections.<JWSAlgorithm>emptySet());
			fail();
		} catch (IllegalArgumentException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testConstructor_nullAcceptable() {
		
		try {
			new DPoPKeySelector(Collections.<JWSAlgorithm>emptySet());
			fail();
		} catch (IllegalArgumentException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testAlgNotAccepted() {
		
		try {
			new DPoPKeySelector(Collections.singleton(JWSAlgorithm.RS256))
				.selectJWSKeys(new JWSHeader(JWSAlgorithm.HS256), new DPoPProofContext(ISSUER));
			fail();
		} catch (KeySourceException e) {
			assertEquals("JWS header algorithm not accepted: HS256", e.getMessage());
		}
	}
	
	
	public void testMissingJWKHeader() {
		
		try {
			new DPoPKeySelector(Collections.singleton(JWSAlgorithm.RS256))
				.selectJWSKeys(new JWSHeader(JWSAlgorithm.RS256), new DPoPProofContext(ISSUER));
			fail();
		} catch (KeySourceException e) {
			assertEquals("Missing JWS jwk header parameter", e.getMessage());
		}
	}
	
	
	public void testAlgAndJWKMismatch() throws JOSEException {
		
		RSAKey jwk = new RSAKeyGenerator(2048).generate();
		
		try {
			new DPoPKeySelector(Collections.singleton(JWSAlgorithm.ES256))
				.selectJWSKeys(
					new JWSHeader.Builder(JWSAlgorithm.ES256)
						.jwk(jwk.toPublicJWK())
						.build(),
					new DPoPProofContext(ISSUER)
				);
			fail();
		} catch (KeySourceException e) {
			assertEquals("JWS header alg / jwk mismatch: alg=ES256 jwk.kty=RSA", e.getMessage());
		}
	}
}
