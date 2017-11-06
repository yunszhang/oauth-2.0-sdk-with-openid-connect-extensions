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


import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;


/**
 * Tests the bearer access token class.
 */
public class BearerAccessTokenTest extends TestCase {


	public void testMinimalConstructor()
		throws Exception {
		
		AccessToken token = new BearerAccessToken("abc");
		
		assertEquals("abc", token.getValue());
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());
		
		assertEquals("Bearer abc", token.toAuthorizationHeader());

		JSONObject json = token.toJSONObject();

		assertEquals("abc", json.get("access_token"));
		assertEquals("Bearer", json.get("token_type"));
		assertEquals(2, json.size());

		token = BearerAccessToken.parse(json);

		assertEquals("abc", token.getValue());
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());

		assertTrue(token.getParameterNames().contains("access_token"));
		assertTrue(token.getParameterNames().contains("token_type"));
		assertEquals(2, token.getParameterNames().size());
	}


	public void testGenerate() {

		AccessToken token = new BearerAccessToken(12);

		assertNotNull(token);

		assertEquals(12, new Base64(token.getValue()).decode().length);
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());

		String header = token.toAuthorizationHeader();
		assertTrue(header.startsWith("Bearer "));
		assertEquals(token.getValue(), header.substring("Bearer ".length()));
	}


	public void testGenerateDefault() {

		AccessToken token = new BearerAccessToken();

		assertNotNull(token);

		assertEquals(32, new Base64(token.getValue()).decode().length);
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());

		String header = token.toAuthorizationHeader();
		assertTrue(header.startsWith("Bearer "));
		assertEquals(token.getValue(), header.substring("Bearer ".length()));
	}


	public void testFullConstructor()
		throws Exception {
		
		Scope scope = Scope.parse("read write");

		AccessToken token = new BearerAccessToken("abc", 1500, scope);
		
		assertEquals("abc", token.getValue());
		assertEquals(1500l, token.getLifetime());
		assertTrue(token.getScope().containsAll(Scope.parse("read write")));
		
		assertEquals("Bearer abc", token.toAuthorizationHeader());

		JSONObject json = token.toJSONObject();

		assertEquals("abc", json.get("access_token"));
		assertEquals("Bearer", json.get("token_type"));
		assertEquals(1500l, json.get("expires_in"));
		assertTrue(Scope.parse((String)json.get("scope")).equals(scope));
		assertEquals(4, json.size());

		token = BearerAccessToken.parse(json);

		assertEquals("abc", json.get("access_token"));
		assertEquals("Bearer", json.get("token_type"));
		assertEquals(1500l, json.get("expires_in"));
		assertTrue(Scope.parse((String)json.get("scope")).equals(scope));
		assertEquals(4, json.size());

		assertTrue(token.getParameterNames().contains("access_token"));
		assertTrue(token.getParameterNames().contains("token_type"));
		assertTrue(token.getParameterNames().contains("expires_in"));
		assertTrue(token.getParameterNames().contains("scope"));
		assertEquals(4, token.getParameterNames().size());
	}
	
	
	public void testParseFromHeader()
		throws Exception {
	
		AccessToken token = AccessToken.parse("Bearer abc");
		
		assertEquals("abc", token.getValue());
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());

		assertTrue(token.getParameterNames().contains("access_token"));
		assertTrue(token.getParameterNames().contains("token_type"));
		assertEquals(2, token.getParameterNames().size());
	}


	public void testParseFromHeader_missing() {

		try {
			AccessToken.parse((String)null);

			fail();

		} catch (ParseException e) {

			assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), e.getErrorObject().getCode());
		}
	}
	
	
	public void testParseFromHeader_missingName() {
	
		try {
			AccessToken.parse("abc");
			
			fail();
			
		} catch (ParseException e) {
		
			assertEquals(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
		}
	}
	
	
	public void testParseFromHeader_missingValue() {
	
		try {
			AccessToken.parse("Bearer ");
			
			fail();
			
		} catch (ParseException e) {

			assertEquals(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
		}
	}
	
	
	public void testParseFromQueryParameters()
		throws Exception {
		
		Map<String,String> params = new HashMap<>();
		params.put("access_token", "abc");
		
		assertEquals("abc", BearerAccessToken.parse(params).getValue());
	}
	
	
	public void testParseFromQueryParameters_missing() {
		
		Map<String,String> params = new HashMap<>();
		params.put("some_param", "abc");
		
		try {
			BearerAccessToken.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing access token parameter", e.getMessage());
			assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), e.getErrorObject().getCode());
		}
	}
	
	
	public void testParseFromQueryParameters_empty() {
		
		Map<String,String> params = new HashMap<>();
		params.put("access_token", "");
		
		try {
			BearerAccessToken.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Blank / empty access token", e.getMessage());
			assertEquals(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
		}
	}


	public void testParseFromHTTPRequest()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://c2id.com/reg/123"));
		httpRequest.setAuthorization("Bearer abc");

		BearerAccessToken accessToken = BearerAccessToken.parse(httpRequest);

		assertEquals("abc", accessToken.getValue());
	}


	public void testParseFromHTTPRequest_missing()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://c2id.com/reg/123"));

		try {
			BearerAccessToken.parse(httpRequest);
			fail();

		} catch (ParseException e) {

			assertEquals(401, e.getErrorObject().getHTTPStatusCode());
			assertNull(e.getErrorObject().getCode());
		}
	}


	public void testParseFromHTTPRequest_invalid()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://c2id.com/reg/123"));
		httpRequest.setAuthorization("Bearer");

		try {
			BearerAccessToken.parse(httpRequest);
			fail();

		} catch (ParseException e) {

			assertEquals(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
		}
	}
}
