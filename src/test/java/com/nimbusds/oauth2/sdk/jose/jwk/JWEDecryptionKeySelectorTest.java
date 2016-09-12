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

package com.nimbusds.oauth2.sdk.jose.jwk;


import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Identifier;
import junit.framework.TestCase;
import org.junit.Assert;


/**
 * Tests selector for JWE decryption keys.
 */
public class JWEDecryptionKeySelectorTest extends TestCase {
	

	public void testForRSA_OAEP()
		throws Exception {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);

		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.keyUse(KeyUse.ENCRYPTION)
			.build();

		keyPair = keyPairGenerator.generateKeyPair();

		RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("2")
			.keyUse(KeyUse.ENCRYPTION)
			.build();

		Identifier id = new ClientID("123");

		JWEDecryptionKeySelector keySelector = new JWEDecryptionKeySelector(
			id,
			JWEAlgorithm.RSA_OAEP,
			EncryptionMethod.A128CBC_HS256,
			new ImmutableJWKSet(id, new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2))));

		assertEquals(id, keySelector.getIdentifier());
		assertEquals(JWEAlgorithm.RSA_OAEP, keySelector.getExpectedJWEAlgorithm());
		assertEquals(EncryptionMethod.A128CBC_HS256, keySelector.getExpectedJWEEncryptionMethod());

		// Test matcher
		JWKMatcher m = keySelector.createJWKMatcher(new JWEHeader.Builder(
			JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256)
			.keyID("1")
			.build());

		assertTrue(m.getKeyTypes().contains(KeyType.RSA));
		assertTrue(m.getKeyIDs().contains("1"));
		assertTrue(m.getKeyUses().contains(KeyUse.ENCRYPTION));
		assertTrue(m.getAlgorithms().contains(JWEAlgorithm.RSA_OAEP));

		m = keySelector.createJWKMatcher(new JWEHeader.Builder(
			JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256)
			.keyID("2")
			.build());

		assertTrue(m.getKeyTypes().contains(KeyType.RSA));
		assertTrue(m.getKeyIDs().contains("2"));
		assertTrue(m.getKeyUses().contains(KeyUse.ENCRYPTION));
		assertTrue(m.getAlgorithms().contains(JWEAlgorithm.RSA_OAEP));

		m = keySelector.createJWKMatcher(new JWEHeader.Builder(
			JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256)
			.keyID("1")
			.build());

		assertNull(m);

		m = keySelector.createJWKMatcher(new JWEHeader.Builder(
			JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM)
			.keyID("1")
			.build());

		assertNull(m);

		// Select for good header with key ID
		List<Key> candidates = keySelector.selectJWEKeys(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256).keyID("1").build(), null);
		Assert.assertArrayEquals(rsaJWK1.toRSAPrivateKey().getEncoded(), candidates.get(0).getEncoded());
		assertEquals(1, candidates.size());

		// Select for good header without key ID
		candidates = keySelector.selectJWEKeys(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256).build(), null);
		Assert.assertArrayEquals(rsaJWK1.toRSAPrivateKey().getEncoded(), candidates.get(0).getEncoded());
		Assert.assertArrayEquals(rsaJWK2.toRSAPrivateKey().getEncoded(), candidates.get(1).getEncoded());
		assertEquals(2, candidates.size());

		// Select for header with invalid key ID
		candidates = keySelector.selectJWEKeys(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256).keyID("3").build(), null);
		assertTrue(candidates.isEmpty());

		// Select for header with unexpected JWE alg
		candidates = keySelector.selectJWEKeys(new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256).keyID("1").build(), null);
		assertTrue(candidates.isEmpty());

		// Select for header with unexpected JWE enc
		candidates = keySelector.selectJWEKeys(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM).keyID("1").build(), null);
		assertTrue(candidates.isEmpty());
	}
}
