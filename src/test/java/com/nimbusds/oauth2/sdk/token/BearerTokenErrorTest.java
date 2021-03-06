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
import com.nimbusds.oauth2.sdk.Scope;
import junit.framework.TestCase;


public class BearerTokenErrorTest extends TestCase {


	public void testConstantCodes() {

		assertNull(BearerTokenError.MISSING_TOKEN.getCode());
		assertEquals("invalid_request", BearerTokenError.INVALID_REQUEST.getCode());
		assertEquals("invalid_token", BearerTokenError.INVALID_TOKEN.getCode());
		assertEquals("insufficient_scope", BearerTokenError.INSUFFICIENT_SCOPE.getCode());
	}
	
	
	public void testMinimalConstructor()
		throws ParseException {
		
		String code = "invalid_request";
		String description = "Invalid request";
		BearerTokenError error = new BearerTokenError(code, description);
		assertEquals(AccessTokenType.BEARER, error.getScheme());
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertNull(error.getURI());
		assertEquals(0, error.getHTTPStatusCode());
		assertNull(error.getRealm());
		assertNull(error.getScope());
		
		String wwwHeader = error.toWWWAuthenticateHeader();
		assertEquals("Bearer error=\"invalid_request\", error_description=\"Invalid request\"", wwwHeader);
		
		error = BearerTokenError.parse(wwwHeader);
		
		assertEquals(AccessTokenType.BEARER, error.getScheme());
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertNull(error.getURI());
		assertEquals(0, error.getHTTPStatusCode());
		assertNull(error.getRealm());
		assertNull(error.getScope());
	}
	
	
	public void testPartConstructor()
		throws ParseException {
		
		String code = "invalid_request";
		String description = "Invalid request";
		int statusCode = 400;
		BearerTokenError error = new BearerTokenError(code, description, statusCode);
		assertEquals(AccessTokenType.BEARER, error.getScheme());
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertNull(error.getURI());
		assertEquals(400, error.getHTTPStatusCode());
		assertNull(error.getRealm());
		assertNull(error.getScope());
		
		String wwwHeader = error.toWWWAuthenticateHeader();
		assertEquals("Bearer error=\"invalid_request\", error_description=\"Invalid request\"", wwwHeader);
		
		error = BearerTokenError.parse(wwwHeader);
		assertEquals(AccessTokenType.BEARER, error.getScheme());
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertNull(error.getURI());
		assertEquals(0, error.getHTTPStatusCode());
		assertNull(error.getRealm());
		assertNull(error.getScope());
	}
	
	
	public void testFullConstructor()
		throws ParseException {
		
		String code = "invalid_request";
		String description = "Invalid request";
		int statusCode = 400;
		URI uri = URI.create("https://c2id.com/errors/invalid_request");
		String realm = "c2id.com";
		Scope scope = new Scope("read", "write");
		BearerTokenError error = new BearerTokenError(code, description, statusCode, uri, realm, scope);
		assertEquals(AccessTokenType.BEARER, error.getScheme());
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertEquals(uri, error.getURI());
		assertEquals(400, error.getHTTPStatusCode());
		assertEquals(realm, error.getRealm());
		assertEquals(scope, error.getScope());
		
		String wwwHeader = error.toWWWAuthenticateHeader();
		assertEquals("Bearer realm=\"c2id.com\", error=\"invalid_request\", error_description=\"Invalid request\", error_uri=\"https://c2id.com/errors/invalid_request\", scope=\"read write\"", wwwHeader);
		
		error = BearerTokenError.parse(wwwHeader);
		
		assertEquals(AccessTokenType.BEARER, error.getScheme());
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertEquals(uri, error.getURI());
		assertEquals(0, error.getHTTPStatusCode());
		assertEquals(realm, error.getRealm());
		assertEquals(scope, error.getScope());
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


	public void testEmptyRealm()
		throws Exception {

		String wwwAuth = "Bearer realm=\"\"";

		BearerTokenError error = BearerTokenError.parse(wwwAuth);

		assertEquals(error, BearerTokenError.MISSING_TOKEN);

		assertEquals("", error.getRealm());
		assertNull(error.getCode());
	}


	public void testBlankRealm()
		throws Exception {

		String wwwAuth = "Bearer realm=\" \"";

		BearerTokenError error = BearerTokenError.parse(wwwAuth);

		assertEquals(error, BearerTokenError.MISSING_TOKEN);

		assertEquals(" ", error.getRealm());
		assertNull(error.getCode());
	}


	public void testRealmAtCharLimit256()
		throws Exception {

		StringBuilder sb = new StringBuilder();
		for (int i=0; i < 256; i++) {
			sb.append('x');
		}
		
		String wwwAuth = "Bearer realm=\"" + sb + "\"";

		BearerTokenError error = BearerTokenError.parse(wwwAuth);

		assertEquals(error, BearerTokenError.MISSING_TOKEN);

		assertEquals(sb.toString(), error.getRealm());
		assertNull(error.getCode());
	}


	public void testRealmBeyondCharLimit256()
		throws Exception {

		StringBuilder sb = new StringBuilder();
		for (int i=0; i < 256 + 1; i++) {
			sb.append('x');
		}
		
		String wwwAuth = "Bearer realm=\"" + sb + "\"";

		BearerTokenError error = BearerTokenError.parse(wwwAuth);

		assertEquals(error, BearerTokenError.MISSING_TOKEN);
		assertNull("Too long, not parsed", error.getRealm());
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
	
	
	public void testRealmWithEscapeDoubleQuotes()
		throws Exception {
		
		BearerTokenError error = BearerTokenError.INVALID_TOKEN.setRealm("\"my-realm\"");
		
		assertEquals("\"my-realm\"", error.getRealm());
		
		String wwwAuthHeader = error.toWWWAuthenticateHeader();
		
		assertEquals("Bearer realm=\"\\\"my-realm\\\"\", error=\"invalid_token\", error_description=\"Invalid access token\"", wwwAuthHeader);
		
		BearerTokenError parsed = BearerTokenError.parse(wwwAuthHeader);
		
		assertEquals(error.getRealm(), parsed.getRealm());
	}
	
	
	public void testInvalidCharsInErrorCode() {
		
		try {
			new BearerTokenError("\"invalid_token\"", null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Illegal char(s) in code, see RFC 6749, section 5.2", e.getMessage());
		}
	}
	
	
	public void testInvalidCharsInErrorDescription() {
		
		try {
			new BearerTokenError("invalid_token", "Invalid token: \"abc\"");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Illegal char(s) in description, see RFC 6749, section 5.2", e.getMessage());
		}
	}
	
	
	public void testInvalidCharsInScope() {
		
		try {
			BearerTokenError.INSUFFICIENT_SCOPE.setScope(new Scope("read", "\"write\""));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The scope contains illegal characters, see RFC 6750, section 3", e.getMessage());
		}
	}
	
	
	public void testParseWWWAuthenticateHeader_invalidCharsInErrorCode()
		throws ParseException {
		
		// skip invalid error code
		assertNull(BearerTokenError.parse("Bearer error=\"\"invalid token\"").getCode());
	}
	
	
	public void testIgnoreParseInvalidErrorURI()
		throws ParseException {
		
		BearerTokenError error = BearerTokenError.parse("Bearer error=invalid_token, error_uri=\"a b c\"");
		
		assertEquals(BearerTokenError.INVALID_TOKEN.getCode(), error.getCode());
		assertNull(error.getURI());
	}
	
	
	// Test lenient parsing with comma after Bearer
	//  https://tools.ietf.org/html/rfc6750#section-3.1
	public void testParseWithCommaAfterBearer() throws ParseException {
		
		BearerTokenError error = BearerTokenError.parse("Bearer, error=\"invalid_token\", error_description=\"The Token was expired\"");
		assertEquals("invalid_token", error.getCode());
		assertEquals("The Token was expired", error.getDescription());
		assertNull(error.getRealm());
		assertNull(error.getScope());
		assertEquals("HTTP status code not known", 0, error.getHTTPStatusCode()); // Not known
	}
}
