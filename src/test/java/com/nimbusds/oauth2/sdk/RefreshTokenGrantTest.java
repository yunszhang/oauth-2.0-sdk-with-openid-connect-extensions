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

package com.nimbusds.oauth2.sdk;


import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertNotEquals;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.token.RefreshToken;


/**
 * Tests the refresh token grant.
 */
public class RefreshTokenGrantTest extends TestCase {


	public void testConstructor() {

		RefreshToken refreshToken = new RefreshToken();
		RefreshTokenGrant grant = new RefreshTokenGrant(refreshToken);
		assertEquals(GrantType.REFRESH_TOKEN, grant.getType());
		assertEquals(refreshToken, grant.getRefreshToken());

		Map<String,List<String>> params = grant.toParameters();
		assertEquals(Collections.singletonList(GrantType.REFRESH_TOKEN.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(refreshToken.getValue()), params.get("refresh_token"));
		assertEquals(2, params.size());
	}


	public void testParse()
		throws Exception {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("refresh_token"));
		params.put("refresh_token", Collections.singletonList("abc123"));

		RefreshTokenGrant grant = RefreshTokenGrant.parse(params);
		assertEquals(GrantType.REFRESH_TOKEN, grant.getType());
		assertEquals("abc123", grant.getRefreshToken().getValue());
	}


	public void testParse_missingGrantType() {

		Map<String,List<String>> params = new HashMap<>();
		params.put("refresh_token", Collections.singletonList("abc123"));

		try {
			RefreshTokenGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing grant_type parameter", e.getErrorObject().getDescription());
		}
	}


	public void testParse_unsupportedGrantType() {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("unsupported"));
		params.put("refresh_token", Collections.singletonList("abc123"));

		try {
			RefreshTokenGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode(), e.getErrorObject().getCode());
			assertEquals("Unsupported grant type: The grant_type must be refresh_token", e.getErrorObject().getDescription());
		}
	}


	public void testParse_missingRefreshToken() {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("refresh_token"));

		try {
			RefreshTokenGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing or empty refresh_token parameter", e.getErrorObject().getDescription());
		}
	}


	public void testEquality() {
		
		assertEquals(new RefreshTokenGrant(new RefreshToken("xyz")), new RefreshTokenGrant(new RefreshToken("xyz")));
	}


	public void testInequality() {
		
		assertNotEquals(new RefreshTokenGrant(new RefreshToken("abc")), new RefreshTokenGrant(new RefreshToken("xyz")));
	}
}
