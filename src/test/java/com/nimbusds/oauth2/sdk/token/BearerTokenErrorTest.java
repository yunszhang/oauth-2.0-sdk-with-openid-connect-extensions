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


import java.net.URI;

import com.nimbusds.oauth2.sdk.ParseException;
import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.Scope;


public class BearerTokenErrorTest extends TestCase {


	public void testConstantCodes() {

		assertNull(BearerTokenError.MISSING_TOKEN.getCode());
		assertEquals("invalid_request", BearerTokenError.INVALID_REQUEST.getCode());
		assertEquals("invalid_token", BearerTokenError.INVALID_TOKEN.getCode());
		assertEquals("insufficient_scope", BearerTokenError.INSUFFICIENT_SCOPE.getCode());
	}


	public void testSerializeAndParseWWWAuthHeader()
		throws Exception {

		BearerTokenError error = BearerTokenError.INVALID_TOKEN.setRealm("example.com");

		assertEquals("example.com", error.getRealm());
		assertEquals("invalid_token", error.getCode());

		String wwwAuth = error.toWWWAuthenticateHeader();

		error = BearerTokenError.parse(wwwAuth);

		assertEquals("example.com", error.getRealm());
		assertEquals("invalid_token", error.getCode());
	}


	public void testNullRealm() {

		BearerTokenError error = BearerTokenError.INVALID_REQUEST.setRealm(null);

		assertNull(error.getRealm());
	}


	public void testNoErrorCode()
		throws Exception {

		String wwwAuth = "Bearer realm=\"example.com\"";

		BearerTokenError error = BearerTokenError.parse(wwwAuth);

		assertEquals(error, BearerTokenError.MISSING_TOKEN);

		assertEquals("example.com", error.getRealm());
		assertNull(error.getCode());
	}


	public void testInsufficientScope()
		throws Exception {

		BearerTokenError error = BearerTokenError.INSUFFICIENT_SCOPE;
		error = error.setScope(Scope.parse("offline_access"));

		String wwwAuth = error.toWWWAuthenticateHeader();

		error = BearerTokenError.parse(wwwAuth);

		assertEquals(Scope.parse("offline_access"), error.getScope());
	}


	public void testSetDescription() {

		assertEquals("description", BearerTokenError.INSUFFICIENT_SCOPE.setDescription("description").getDescription());
	}


	public void testAppendDescription() {

		assertEquals("Insufficient scope: offline_access", BearerTokenError.INSUFFICIENT_SCOPE.appendDescription(": offline_access").getDescription());
	}


	public void testSetHTTPStatusCode() {

		assertEquals(400, BearerTokenError.INSUFFICIENT_SCOPE.setHTTPStatusCode(400).getHTTPStatusCode());
	}


	public void testSetURI()
		throws Exception {

		URI uri = new URI("http://example.com");

		assertEquals(uri, BearerTokenError.INSUFFICIENT_SCOPE.setURI(uri).getURI());
	}


	public void testParseInvalidTokenHeader()
		throws Exception {

		String header = "Bearer error=\"invalid_token\", error_description=\"Invalid access token\"";

		BearerTokenError error = BearerTokenError.parse(header);

		assertEquals(BearerTokenError.INVALID_TOKEN, error);
		assertEquals("Invalid access token", error.getDescription());
		assertNull(error.getURI());
		assertNull(error.getRealm());
	}
	
	
	// see https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/197/userinfo-error-response-by-google-not
	public void testParseGoogleBearerTokenError()
		throws Exception {
		
		String header = "Bearer realm=\"https://acounts.google.com/\", error=invalid_token";
		
		BearerTokenError error = BearerTokenError.parse(header);
		assertEquals(BearerTokenError.INVALID_TOKEN, error);
		assertEquals("invalid_token", error.getCode());
		assertNull(error.getDescription());
		assertNull(error.getURI());
		assertEquals("https://acounts.google.com/", error.getRealm());
	}
	
	
	// see https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/197/userinfo-error-response-by-google-not
	public void testParseGoogleBearerTokenError_extended()
		throws Exception {
		
		String header = "Bearer realm=\"https://acounts.google.com/\", error=invalid_token, error_description=\"Invalid access token\"";
		
		BearerTokenError error = BearerTokenError.parse(header);
		assertEquals(BearerTokenError.INVALID_TOKEN, error);
		assertEquals("invalid_token", error.getCode());
		assertEquals("Invalid access token", error.getDescription());
		assertNull(error.getURI());
		assertEquals("https://acounts.google.com/", error.getRealm());
	}
	
	
	public void testToWWWAuthenticateHeaderEscapeDoubleQuotes()
		throws ParseException {
		
		BearerTokenError error = new BearerTokenError(
			"\"invalid_token\"",
			"Invalid token \"abc\"",
			403,
			URI.create("https://c2id.com/api/errors/%22invalid_token%22"),
			"\"realm\"",
			new Scope("\"read\"", "\"write\""));
		
		assertEquals("Bearer realm=\"\\\"realm\\\"\", error=\"\\\"invalid_token\\\"\", error_description=\"Invalid token \\\"abc\\\"\", error_uri=\"https://c2id.com/api/errors/%22invalid_token%22\", scope=\"\\\"read\\\" \\\"write\\\"\"", error.toWWWAuthenticateHeader());
		
		BearerTokenError parsed = BearerTokenError.parse(error.toWWWAuthenticateHeader());
		
		assertEquals(error.getCode(), parsed.getCode());
		assertEquals(error.getDescription(), parsed.getDescription());
		assertEquals(error.getHTTPStatusCode(), parsed.getHTTPStatusCode());
		assertEquals(error.getURI(), parsed.getURI());
		assertEquals(error.getScope(), parsed.getScope());
	}
}
