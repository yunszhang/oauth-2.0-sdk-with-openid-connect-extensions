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

package com.nimbusds.openid.connect.sdk;


import static org.junit.Assert.assertNotEquals;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.Identifier;


public class NonceTest extends TestCase {


	public void testDefaultConstructor() {

		Nonce nonce = new Nonce();

		System.out.println("Generated nonce: " + nonce);

		assertEquals(Identifier.DEFAULT_BYTE_LENGTH, new Base64(nonce.getValue()).decode().length);
	}


	public void testIntConstructor() {

		Nonce nonce =  new Nonce(1);
		assertEquals(1, new Base64(nonce.getValue()).decode().length);
	}


	public void testIntConstructorZero() {

		try {
			new Nonce(0);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The byte length must be a positive integer", e.getMessage());
		}
	}


	public void testIntConstructorNegative() {

		try {
			new Nonce(-1);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The byte length must be a positive integer", e.getMessage());
		}
	}


	public void testEquality() {

		Nonce n1 = new Nonce("abc");
		Nonce n2 = new Nonce("abc");
		
		assertEquals(n1, n2);
	}


	public void testInequality() {

		Nonce n1 = new Nonce("abc");
		Nonce n2 = new Nonce("xyz");
		
		assertNotEquals(n1, n2);
	}
	
	
	public void testNonceRequirement() {
		
		// code flow
		assertFalse(Nonce.isRequired(ResponseType.CODE));
		
		// implicit
		assertTrue(Nonce.isRequired(ResponseType.IDTOKEN));
		assertTrue(Nonce.isRequired(ResponseType.IDTOKEN_TOKEN));
		assertFalse(Nonce.isRequired(ResponseType.TOKEN)); // OAuth 2.0 only
		
		// hybrid
		assertTrue(Nonce.isRequired(ResponseType.CODE_IDTOKEN));
		assertTrue(Nonce.isRequired(ResponseType.CODE_IDTOKEN_TOKEN));
		assertFalse(Nonce.isRequired(ResponseType.CODE_TOKEN));
	}
}