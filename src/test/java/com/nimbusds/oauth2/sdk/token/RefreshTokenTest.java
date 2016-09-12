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

package com.nimbusds.oauth2.sdk.token;


import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64;


/**
 * Tests the refresh token class.
 */
public class RefreshTokenTest extends TestCase {


	public void testValueConstructor() {

		RefreshToken rt = new RefreshToken("abc");
		assertEquals("abc", rt.getValue());
		assertTrue(rt.getParameterNames().contains("refresh_token"));
		assertEquals(1, rt.getParameterNames().size());
	}


	public void testGeneratorConstructor() {

		RefreshToken rt = new RefreshToken(16);
		assertEquals(16, new Base64(rt.getValue()).decode().length);
		assertTrue(rt.getParameterNames().contains("refresh_token"));
		assertEquals(1, rt.getParameterNames().size());
	}
}
