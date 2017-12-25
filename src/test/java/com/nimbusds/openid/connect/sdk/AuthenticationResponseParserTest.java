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


import java.net.URI;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.State;


/**
 * Tests the OpenID Connect authentication response parser.
 */
public class AuthenticationResponseParserTest extends TestCase {


	public void testParseSuccess()
		throws Exception {

		URI redirectURI = new URI("https://example.com/in");
		AuthorizationCode code = new AuthorizationCode("123");
		State state = new State("xyz");

		AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(
			redirectURI,
			code,
			null,
			null,
			state,
			null,
			null);

		HTTPResponse httpResponse = successResponse.toHTTPResponse();

		AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(state, response.getState());

		successResponse = response.toSuccessResponse();
		assertEquals(code, successResponse.getAuthorizationCode());
		assertEquals(state, successResponse.getState());
	}


	public void testParseError()
		throws Exception {

		URI redirectURI = new URI("https://example.com/in");
		State state = new State("xyz");

		AuthenticationErrorResponse errorResponse = new AuthenticationErrorResponse(
			redirectURI,
			OAuth2Error.ACCESS_DENIED,
			state,
			ResponseMode.QUERY);

		assertFalse(errorResponse.indicatesSuccess());

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(state, response.getState());

		errorResponse = response.toErrorResponse();
		assertEquals(OAuth2Error.ACCESS_DENIED, errorResponse.getErrorObject());
		assertEquals(state, errorResponse.getState());
	}


	// see https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/162/authenticationresponseparser-does-not
	public void testParseAbsoluteURI()
		throws Exception {

		URI redirectURI = URI.create("http:///?code=Qcb0Orv1&state=af0ifjsldkj");

		AuthenticationResponse response = AuthenticationResponseParser.parse(redirectURI);

		AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse)response;

		assertEquals("Qcb0Orv1", successResponse.getAuthorizationCode().getValue());
		assertEquals("af0ifjsldkj", successResponse.getState().getValue());
	}
}
