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


import java.util.Arrays;
import java.util.LinkedHashSet;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;


public class UserInfoErrorResponseTest extends TestCase {


	public void testStandardErrors() {

		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INVALID_REQUEST));
		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.MISSING_TOKEN));
		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INVALID_TOKEN));
		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INSUFFICIENT_SCOPE));
		assertEquals(4, UserInfoErrorResponse.getStandardErrors().size());
	}


	public void testBearerConstructAndParse()
		throws Exception {

		BearerTokenError bearerTokenError = BearerTokenError.INVALID_TOKEN
			.setRealm("c2id.com")
			.setScope(new Scope(OIDCScopeValue.OPENID));
		
		UserInfoErrorResponse errorResponse = new UserInfoErrorResponse(bearerTokenError);

		assertFalse(errorResponse.indicatesSuccess());

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		assertEquals(401, httpResponse.getStatusCode());

		assertEquals("Bearer realm=\"c2id.com\", error=\"invalid_token\", error_description=\"Invalid access token\", scope=\"openid\"", httpResponse.getWWWAuthenticate());

		errorResponse = UserInfoErrorResponse.parse(httpResponse);

		assertFalse(errorResponse.indicatesSuccess());
		
		BearerTokenError parsedBearerTokenError = (BearerTokenError) errorResponse.getErrorObject();
		
		assertEquals(401, parsedBearerTokenError.getHTTPStatusCode());
		
		assertEquals(bearerTokenError.getScheme(), parsedBearerTokenError.getScheme());
		assertEquals(bearerTokenError.getRealm(), parsedBearerTokenError.getRealm());
		assertEquals(bearerTokenError.getCode(), parsedBearerTokenError.getCode());
		assertEquals(bearerTokenError.getDescription(), parsedBearerTokenError.getDescription());
		assertEquals(bearerTokenError.getURI(), parsedBearerTokenError.getURI());
		assertEquals(bearerTokenError.getScope(), parsedBearerTokenError.getScope());
	}
	
	
	public void testDPoPConstructAndParse()
		throws Exception {

		DPoPTokenError dPoPTokenError = DPoPTokenError.INVALID_TOKEN
			.setJWSAlgorithms(new LinkedHashSet<>(Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.PS256)));
		
		UserInfoErrorResponse errorResponse = new UserInfoErrorResponse(dPoPTokenError);

		assertFalse(errorResponse.indicatesSuccess());

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		assertEquals(401, httpResponse.getStatusCode());

		assertEquals("DPoP error=\"invalid_token\", error_description=\"Invalid access token\", algs=\"RS256 PS256\"", httpResponse.getWWWAuthenticate());

		errorResponse = UserInfoErrorResponse.parse(httpResponse);

		assertFalse(errorResponse.indicatesSuccess());

		DPoPTokenError parsedDPoPError = (DPoPTokenError) errorResponse.getErrorObject();
		
		assertEquals(401, parsedDPoPError.getHTTPStatusCode());
		
		assertEquals(dPoPTokenError.getScheme(), parsedDPoPError.getScheme());
		assertEquals(dPoPTokenError.getCode(), parsedDPoPError.getCode());
		assertEquals(dPoPTokenError.getDescription(), parsedDPoPError.getDescription());
		assertEquals(dPoPTokenError.getURI(), parsedDPoPError.getURI());
		assertEquals(dPoPTokenError.getJWSAlgorithms(), parsedDPoPError.getJWSAlgorithms());
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
