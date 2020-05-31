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


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


/**
 * Tests the UserInfo error response class.
 */
public class UserInfoErrorResponseTest extends TestCase {


	public void testStandardErrors() {

		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INVALID_REQUEST));
		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.MISSING_TOKEN));
		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INVALID_TOKEN));
		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INSUFFICIENT_SCOPE));
		assertEquals(4, UserInfoErrorResponse.getStandardErrors().size());
	}


	public void testConstructAndParse()
		throws Exception {

		UserInfoErrorResponse errorResponse = new UserInfoErrorResponse(BearerTokenError.INVALID_TOKEN);

		assertFalse(errorResponse.indicatesSuccess());

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		assertEquals(401, httpResponse.getStatusCode());

		assertEquals("Bearer error=\"invalid_token\", error_description=\"Invalid access token\"", httpResponse.getWWWAuthenticate());

		errorResponse = UserInfoErrorResponse.parse(httpResponse);

		assertFalse(errorResponse.indicatesSuccess());

		assertEquals(BearerTokenError.INVALID_TOKEN, errorResponse.getErrorObject());
	}
	
	
	public void testOtherError()
		throws Exception {
		
		ErrorObject error = new ErrorObject("conflict", "Couldn't encrypt UserInfo JWT: Missing / expired client_secret", 409);
		
		UserInfoErrorResponse errorResponse = new UserInfoErrorResponse(error);
		
		assertEquals(error, errorResponse.getErrorObject());
		
		HTTPResponse httpResponse = errorResponse.toHTTPResponse();
		assertEquals(409, httpResponse.getStatusCode());
		assertEquals("application/json; charset=UTF-8", httpResponse.getEntityContentType().toString());
		assertNull(httpResponse.getWWWAuthenticate());
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		assertEquals(error.getCode(), jsonObject.get("error"));
		assertEquals(error.getDescription(), jsonObject.get("error_description"));
		assertEquals(2, jsonObject.size());
		
		errorResponse = UserInfoErrorResponse.parse(httpResponse);
		
		assertEquals(error.getCode(), errorResponse.getErrorObject().getCode());
		assertEquals(error.getDescription(), errorResponse.getErrorObject().getDescription());
		assertNull(errorResponse.getErrorObject().getURI());
		assertEquals(error.getHTTPStatusCode(), errorResponse.getErrorObject().getHTTPStatusCode());
	}
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/299/http-status-code-missing-in-case-userinfo
	public void testBearerTokenErrorOverrideHTTPStatusCode()
		throws ParseException {
	
		// HTTP/1.1 401 Unauthorized
		// WWW-Authenticate: Bearer, error="invalid_token", error_description="The Token was expired"
		
		HTTPResponse httpResponse = new HTTPResponse(401);
		httpResponse.setWWWAuthenticate("Bearer, error=\"invalid_token\", error_description=\"The Token was expired\"");
		
		UserInfoErrorResponse errorResponse = UserInfoErrorResponse.parse(httpResponse);
		
		BearerTokenError bte = (BearerTokenError)errorResponse.getErrorObject();
		assertEquals(401, bte.getHTTPStatusCode());
		assertEquals("invalid_token", bte.getCode());
		assertEquals("The Token was expired", bte.getDescription());
		assertNull(bte.getRealm());
		assertNull(bte.getScope());
	}
}
