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

package com.nimbusds.oauth2.sdk.auth;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;

import static org.junit.Assert.assertArrayEquals;

import com.nimbusds.jose.util.Base64;
import junit.framework.TestCase;


/**
 * Tests the secret / password class.
 */
public class SecretTest extends TestCase {


	public void testFullConstructor() {

		Date exp = new Date(new Date().getTime() + 3600*1000);
		Secret secret = new Secret("password", exp);
		assertEquals("password", secret.getValue());
		assertEquals(exp, secret.getExpirationDate());
		assertEquals(new Secret("password"), secret);
	}


	public void testEmptySecret() {

		Secret secret = new Secret("");
		assertEquals("", secret.getValue());
		assertEquals(0, secret.getValueBytes().length);
	}


	public void testErase() {

		Secret secret = new Secret("password");
		assertEquals("password".length(), secret.getValue().length());
		secret.erase();
		assertNull(secret.getValue());
	}


	public void testNotExpired() {

		Date future = new Date(new Date().getTime() + 3600*1000);
		Secret secret = new Secret("password", future);
		assertFalse(secret.expired());
	}


	public void testExpired() {

		Date past = new Date(new Date().getTime() - 3600*1000);
		Secret secret = new Secret("password", past);
		assertTrue(secret.expired());
	}


	public void testEquality() {

		assertTrue(new Secret("password").equals(new Secret("password")));
		assertTrue(new Secret("").equals(new Secret("")));

		// Compare erased secrets
		Secret s1 = new Secret("password");
		s1.erase();

		Secret s2 = new Secret("password");
		s2.erase();

		assertFalse(s1.equals(s2));

		// Ensure expiration date is ignored in comparison
		final Date now = new Date();
		final Date tomorrow = new Date(now.getTime() + 24*60*60*1000L);
		assertTrue(new Secret("password", tomorrow).equals(new Secret("password", new Date())));
	}


	public void testInequality() {

		assertFalse(new Secret("password").equals(new Secret("passw0rd")));
		assertFalse(new Secret("password").equals(new Secret("")));

		Secret erased = new Secret("password");
		erased.erase();

		assertFalse(erased.equals(new Secret("password")));
	}
	
	
	public void testGenerateDefault() {
		
		Secret secret = new Secret();
		
		// Base64 < encoded byte length
		assertEquals(Secret.DEFAULT_BYTE_LENGTH, new Base64(secret.getValue()).decode().length);
	}


	public void testGenerate() {

		Secret secret = new Secret(32);

		// Base64 < encoded byte length
		assertEquals(32, new Base64(secret.getValue()).decode().length);
		assertEquals(43, secret.getValueBytes().length);
	}
	
	
	public void testBase64URLAlphabet() {
		
		String base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		
		// 100 trials
		for (int i=0; i < 100; i++) {
			
			Secret secret = new Secret();
			
			for (char c: secret.getValue().toCharArray()) {
				
				assertTrue(base64URLAlphabet.contains(c + ""));
			}
		}
	}
	
	
	public void testSHA256()
		throws NoSuchAlgorithmException {
		
		Secret secret = new Secret();
		byte[] value = secret.getValueBytes();
		
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		assertArrayEquals(sha256.digest(value), secret.getSHA256());
		
		// Erase value
		secret.erase();
		assertNull(secret.getSHA256());
	}
	
	
	public void testEqualsSHA256() {
		
		Secret secret = new Secret();
		Secret anotherSecret = new Secret(secret.getValue());
		
		assertTrue(secret.equals(anotherSecret));
		
		assertTrue(secret.equalsSHA256Based(anotherSecret));
		
		secret.erase();
		assertFalse(secret.equalsSHA256Based(anotherSecret));
		
		anotherSecret.erase();
		assertFalse(secret.equalsSHA256Based(anotherSecret));
		
		assertFalse(secret.equalsSHA256Based(null));
	}
}
