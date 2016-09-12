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
 * Code challenge methods test.
 */
public class CodeChallengeMethodTest extends TestCase {
	

	public void testConstants() {

		assertEquals("plain", CodeChallengeMethod.PLAIN.getValue());
		assertEquals("S256", CodeChallengeMethod.S256.getValue());
	}


	public void testDefault() {

		assertTrue(CodeChallengeMethod.PLAIN.equals(CodeChallengeMethod.getDefault()));
	}


	public void testParse() {

		assertTrue(CodeChallengeMethod.PLAIN.equals(CodeChallengeMethod.parse("plain")));
		assertTrue(CodeChallengeMethod.S256.equals(CodeChallengeMethod.parse("S256")));
		assertTrue(new CodeChallengeMethod("S512").equals(CodeChallengeMethod.parse("S512")));
	}


	public void testParseEquality() {

		assertTrue(CodeChallengeMethod.parse("plain") == CodeChallengeMethod.PLAIN);
		assertTrue(CodeChallengeMethod.parse("S256") == CodeChallengeMethod.S256);
	}
}
