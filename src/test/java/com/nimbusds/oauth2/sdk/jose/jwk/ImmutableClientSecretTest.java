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


import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.List;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import junit.framework.TestCase;
import org.junit.Assert;


/**
 * Tests immutable client_secret as JWK set.
 */
public class ImmutableClientSecretTest extends TestCase {
	

	public void testSecretConstructor() {

		ClientID id = new ClientID("123");
		Secret secret = new Secret("xyz");

		ImmutableClientSecret clientSecret = new ImmutableClientSecret(id, secret);

		assertEquals(id, clientSecret.getOwner());
		assertEquals(secret.getValue(), new String(clientSecret.getClientSecret().toByteArray(), Charset.forName("UTF-8")));

		JWKSet jwkSet = clientSecret.getJWKSet();
		assertEquals(secret.getValue(), new String(((OctetSequenceKey)jwkSet.getKeys().get(0)).toByteArray(), Charset.forName("UTF-8")));
		assertEquals(1, jwkSet.getKeys().size());
	}


	public void testOctConstructor() {

		ClientID id = new ClientID("123");

		byte[] secretBytes = new byte[32];
		new SecureRandom().nextBytes(secretBytes);

		ImmutableClientSecret clientSecret = new ImmutableClientSecret(id, new OctetSequenceKey.Builder(secretBytes).build());

		assertEquals(id, clientSecret.getOwner());
		Assert.assertArrayEquals(secretBytes, clientSecret.getClientSecret().toByteArray());

		JWKSet jwkSet = clientSecret.getJWKSet();
		Assert.assertArrayEquals(secretBytes, ((OctetSequenceKey)jwkSet.getKeys().get(0)).toByteArray());
		assertEquals(1, jwkSet.getKeys().size());
	}


	public void testSelect() {

		ClientID id = new ClientID("123");

		byte[] secretBytes = new byte[32];
		new SecureRandom().nextBytes(secretBytes);

		ImmutableClientSecret clientSecret = new ImmutableClientSecret(id, new OctetSequenceKey.Builder(secretBytes).build());

		List<JWK> matches = clientSecret.get(id, new JWKSelector(new JWKMatcher.Builder().keyType(KeyType.OCT).build()));
		Assert.assertArrayEquals(secretBytes, ((OctetSequenceKey)matches.get(0)).toByteArray());
		assertEquals(1, matches.size());
	}


	public void testSelectIgnoreOwnerOnSelect() {

		ClientID id = new ClientID("123");

		byte[] secretBytes = new byte[32];
		new SecureRandom().nextBytes(secretBytes);

		ImmutableClientSecret clientSecret = new ImmutableClientSecret(id, new OctetSequenceKey.Builder(secretBytes).build());

		List<JWK> matches = clientSecret.get(new ClientID("xxx"), new JWKSelector(new JWKMatcher.Builder().keyType(KeyType.OCT).build()));
		Assert.assertArrayEquals(secretBytes, ((OctetSequenceKey)matches.get(0)).toByteArray());
		assertEquals(1, matches.size());
	}
}
