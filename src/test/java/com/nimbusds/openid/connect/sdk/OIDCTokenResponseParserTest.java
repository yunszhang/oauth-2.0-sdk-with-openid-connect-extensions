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


import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import junit.framework.TestCase;


/**
 * Tests the OpenID Connect token response parser.
 */
public class OIDCTokenResponseParserTest extends TestCase {


	// Example ID token from OIDC Standard
	private static final String ID_TOKEN_STRING =
		"eyJhbGciOiJSUzI1NiJ9.ew0KICAgICJpc3MiOiAiaHR0cDovL"+
		"3NlcnZlci5leGFtcGxlLmNvbSIsDQogICAgInVzZXJfaWQiOiAiMjQ4Mjg5NzYxM"+
		"DAxIiwNCiAgICAiYXVkIjogInM2QmhkUmtxdDMiLA0KICAgICJub25jZSI6ICJuL"+
		"TBTNl9XekEyTWoiLA0KICAgICJleHAiOiAxMzExMjgxOTcwLA0KICAgICJpYXQiO"+
		"iAxMzExMjgwOTcwDQp9.lsQI_KNHpl58YY24G9tUHXr3Yp7OKYnEaVpRL0KI4szT"+
		"D6GXpZcgxIpkOCcajyDiIv62R9rBWASV191Akk1BM36gUMm8H5s8xyxNdRfBViCa"+
		"xTqHA7X_vV3U-tSWl6McR5qaSJaNQBpg1oGPjZdPG7zWCG-yEJC4-Fbx2FPOS7-h"+
		"5V0k33O5Okd-OoDUKoFPMd6ur5cIwsNyBazcsHdFHqWlCby5nl_HZdW-PHq0gjzy"+
		"JydB5eYIvOfOHYBRVML9fKwdOLM2xVxJsPwvy3BqlVKc593p2WwItIg52ILWrc6A"+
		"tqkqHxKsAXLVyAoVInYkl_NDBkCqYe2KgNJFzfEC8g";


	public static JWT ID_TOKEN;


	static {
		try {
			ID_TOKEN = JWTParser.parse(ID_TOKEN_STRING);
		} catch (Exception e) {
			ID_TOKEN = null;
		}
	}


	public void testParseSuccess()
		throws Exception {

		OIDCTokens tokens = new OIDCTokens(
			ID_TOKEN,
			new BearerAccessToken("abc123"),
			new RefreshToken("def456"));

		OIDCTokenResponse response = new OIDCTokenResponse(tokens);

		assertEquals(tokens, response.getOIDCTokens());
		assertEquals(tokens, response.getTokens());

		HTTPResponse httpResponse = response.toHTTPResponse();

		TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

		assertTrue(tokenResponse.indicatesSuccess());

		response = (OIDCTokenResponse)tokenResponse.toSuccessResponse();

		assertEquals("abc123", response.getTokens().getAccessToken().getValue());
		assertEquals("def456", response.getTokens().getRefreshToken().getValue());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDTokenString());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDToken().serialize());
	}
	
	
	// Token response with no id_token (e.g. in response to a refresh_token grant)
	public void testParseSuccess_noIDToken()
		throws Exception {
		
		OIDCTokens tokens = new OIDCTokens(
			new BearerAccessToken("abc123"),
			new RefreshToken("def456"));
		
		OIDCTokenResponse response = new OIDCTokenResponse(tokens);
		
		assertEquals(tokens, response.getOIDCTokens());
		assertEquals(tokens, response.getTokens());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		
//		System.out.println(httpResponse.getContent());
		
		TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);
		
		assertTrue(tokenResponse.indicatesSuccess());
		
		response = (OIDCTokenResponse)tokenResponse.toSuccessResponse();
		
		assertEquals("abc123", response.getTokens().getAccessToken().getValue());
		assertEquals("def456", response.getTokens().getRefreshToken().getValue());
		assertNull(response.getOIDCTokens().getIDToken());
		assertNull(response.getOIDCTokens().getIDTokenString());
	}


	public void testParseError()
		throws Exception {

		TokenErrorResponse response = new TokenErrorResponse(OAuth2Error.INVALID_GRANT);

		HTTPResponse httpResponse = response.toHTTPResponse();

		TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

		assertFalse(tokenResponse.indicatesSuccess());
		response = tokenResponse.toErrorResponse();
		assertEquals(OAuth2Error.INVALID_GRANT, response.getErrorObject());
	}
}
