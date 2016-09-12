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


import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Tests the Nonce class.
 */
public class NonceTest extends TestCase {


	public void testDefaultConstructor() {

		Nonce nonce = new Nonce();

		System.out.println("Generated nonce: " + nonce);

		assertEquals(Identifier.DEFAULT_BYTE_LENGTH, new Base64(nonce.getValue()).decode().length);
	}


	public void testIntConstructor() {

		Nonce nonce =  new Nonce(1);

		System.out.println("Generated nonce: " + nonce);
		assertEquals(1, new Base64(nonce.getValue()).decode().length);

	}


	public void testIntConstructorZero() {

		try {
			new Nonce(0);

			fail();

		} catch (IllegalArgumentException e) {

			// ok
		}
	}


	public void testIntConstructorNegative() {

		try {
			new Nonce(-1);

			fail();

		} catch (IllegalArgumentException e) {

			// ok
		}
	}


	public void testEquality() {

		Nonce n1 = new Nonce("abc");
		Nonce n2 = new Nonce("abc");

		assertTrue(n1.equals(n2));
	}


	public void testInequality() {

		Nonce n1 = new Nonce("abc");
		Nonce n2 = new Nonce("xyz");

		assertFalse(n1.equals(n2));
	}
}