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

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;


/**
 * Tests the token pair class.
 */
public class TokensTest extends TestCase {


	public void testAllDefined()
		throws ParseException {

		AccessToken accessToken = new BearerAccessToken(60l, Scope.parse("openid email"));
		RefreshToken refreshToken = new RefreshToken();

		Tokens tokens = new Tokens(accessToken, refreshToken);

		assertEquals(accessToken, tokens.getAccessToken());
		assertEquals(accessToken, tokens.getBearerAccessToken());
		assertEquals(refreshToken, tokens.getRefreshToken());

		assertTrue(tokens.getParameterNames().contains("token_type"));
		assertTrue(tokens.getParameterNames().contains("access_token"));
		assertTrue(tokens.getParameterNames().contains("expires_in"));
		assertTrue(tokens.getParameterNames().contains("scope"));
		assertTrue(tokens.getParameterNames().contains("refresh_token"));
		assertEquals(5, tokens.getParameterNames().size());

		JSONObject jsonObject = tokens.toJSONObject();
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(accessToken.getValue(), jsonObject.get("access_token"));
		assertEquals(60l, jsonObject.get("expires_in"));
		assertEquals("openid email", jsonObject.get("scope"));
		assertEquals(refreshToken.getValue(), jsonObject.get("refresh_token"));
		assertEquals(5, jsonObject.size());

		tokens = Tokens.parse(jsonObject);

		assertEquals(accessToken.getValue(), tokens.getAccessToken().getValue());
		assertEquals(accessToken.getLifetime(), tokens.getAccessToken().getLifetime());
		assertEquals(accessToken.getScope(), tokens.getAccessToken().getScope());
		assertEquals(refreshToken.getValue(), tokens.getRefreshToken().getValue());
	}


	public void testMinimalAccessTokenOnly()
		throws ParseException {

		AccessToken accessToken = new BearerAccessToken();

		Tokens tokens = new Tokens(accessToken, null);

		assertEquals(accessToken, tokens.getAccessToken());
		assertEquals(accessToken, tokens.getBearerAccessToken());
		assertNull(tokens.getRefreshToken());

		assertTrue(tokens.getParameterNames().contains("token_type"));
		assertTrue(tokens.getParameterNames().contains("access_token"));
		assertEquals(2, tokens.getParameterNames().size());

		JSONObject jsonObject = tokens.toJSONObject();
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(accessToken.getValue(), jsonObject.get("access_token"));
		assertEquals(2, jsonObject.size());

		tokens = Tokens.parse(jsonObject);

		assertEquals(accessToken.getValue(), tokens.getAccessToken().getValue());
		assertEquals(accessToken.getLifetime(), tokens.getAccessToken().getLifetime());
		assertEquals(accessToken.getScope(), tokens.getAccessToken().getScope());
		assertNull(tokens.getRefreshToken());
	}


	public void testMissingAccessTokenException() {

		try {
			new Tokens(null, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The access token must not be null", e.getMessage());
		}
	}
}