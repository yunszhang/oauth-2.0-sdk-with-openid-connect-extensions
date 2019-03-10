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

package com.nimbusds.oauth2.sdk.device;

import junit.framework.TestCase;

import org.eclipse.jetty.server.Authentication.User;

import com.nimbusds.jose.util.Base64;

/**
 * Tests generation and comparison of user codes
 */
public class UserCodeTest extends TestCase {

	public void testValueConstructor() {

		String value = "abc";

		UserCode code = new UserCode(value);

		assertEquals(value, code.getValue());
		assertEquals(value, code.toString());
		assertEquals(code.getCharset(), UserCode.LETTER_CHAR_SET);
		assertEquals("ABC", code.getStrippedValue(), code.getCharset());
	}


	public void testValueAndCharsetConstructor() {

		String value = "12345678";

		UserCode code = new UserCode(value, UserCode.DIGIT_CHAR_SET);

		assertEquals(value, code.getValue());
		assertEquals(value, code.toString());
		assertEquals(code.getCharset(), UserCode.DIGIT_CHAR_SET);
		assertEquals("12345678", code.getStrippedValue(), code.getCharset());
	}


	public void testEmptyValue() {

		try {
			new UserCode("");

			fail("Failed to raise exception");

		} catch (IllegalArgumentException e) {

			// ok
		}
	}


	public void testEquality() {

		UserCode c1 = new UserCode("abc", UserCode.LETTER_CHAR_SET);

		UserCode c2 = new UserCode("abc", UserCode.LETTER_CHAR_SET);

		assertTrue(c1.equals(c2));
	}


	public void testEqualityStripped() {

		UserCode c1 = new UserCode("abc-def", UserCode.LETTER_CHAR_SET);

		UserCode c2 = new UserCode("1ABCDEF8", UserCode.LETTER_CHAR_SET);

		assertTrue(c1.equals(c2));
	}


	public void testInequality() {

		UserCode c1 = new UserCode("abc", UserCode.LETTER_CHAR_SET);

		UserCode c2 = new UserCode("def", UserCode.LETTER_CHAR_SET);

		assertFalse(c1.equals(c2));
	}


	public void testInequalityNull() {

		UserCode c1 = new UserCode("abc", UserCode.LETTER_CHAR_SET);

		assertFalse(c1.equals(null));
	}


	public void testHashCode() {

		UserCode c1 = new UserCode("abc");

		UserCode c2 = new UserCode("abc");

		assertEquals(c1.hashCode(), c2.hashCode());
	}


	public void testGeneration() {

		UserCode code = new UserCode();

		System.out.println("Random user code (default length): " + code);

		assertEquals(8 + 1, code.toString().length());
		assertEquals(8, code.getStrippedValue().length());
	}


	public void testGenerationVarLengthAndCharset() {

		UserCode code = new UserCode(UserCode.DIGIT_CHAR_SET, 16);

		System.out.println("Random user code (16 char length): " + code);

		assertEquals(16 + 3, code.toString().length());
		assertEquals(16, code.getStrippedValue().length());
	}


	public void testJSONValue() {

		UserCode code = new UserCode("abc");

		String json = code.toJSONString();

		System.out.println("\"user_code\":" + json);

		assertEquals("\"abc\"", json);
	}
}
