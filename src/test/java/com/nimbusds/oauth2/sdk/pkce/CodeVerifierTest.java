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

package com.nimbusds.oauth2.sdk.pkce;


import junit.framework.TestCase;


/**
 * Code verifier test.
 */
public class CodeVerifierTest extends TestCase {


	public void testLengthLimitConstants() {

		assertEquals(43, CodeVerifier.MIN_LENGTH);
		assertEquals(128, CodeVerifier.MAX_LENGTH);
	}


	public void testDefaultConstructor() {

		CodeVerifier verifier = new CodeVerifier();
		assertEquals(43, verifier.getValue().length());
	}


	public void testEquality() {

		CodeVerifier verifier = new CodeVerifier();

		assertTrue(verifier.equals(new CodeVerifier(verifier.getValue())));
	}


	public void testInequality() {

		assertFalse(new CodeVerifier().equals(new CodeVerifier()));
		assertFalse(new CodeVerifier().equals(null));
	}


	// https://tools.ietf.org/html/rfc7636#page-8
	//
	// code_verifier = high-entropy cryptographic random STRING using the
	// unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
	// from Section 2.3 of [RFC3986], with a minimum length of 43 characters
	// and a maximum length of 128 characters.
	public void testValidCharacters() {

		// check ascii char
		for (char c = 0; c < 128; c++) {

			if (c >= 0x41 && c <= 0x5a) {
				assertTrue(CodeVerifier.isLegal(c));
			} else if (c >= 0x61 && c <= 0x7a) {
				assertTrue(CodeVerifier.isLegal(c));
			} else if (c >= 0x30 && c <= 0x39) {
				assertTrue(CodeVerifier.isLegal(c));
			} else if (c == '-' || c == '.' || c == '_' || c == '~') {
				assertTrue(CodeVerifier.isLegal(c));
			} else {
				assertFalse(CodeVerifier.isLegal(c));
			}
		}

		// check non-ascii char
		for (char c = 128; c <= 256; c++) {
			assertFalse(CodeVerifier.isLegal(c));
		}

	}
}
