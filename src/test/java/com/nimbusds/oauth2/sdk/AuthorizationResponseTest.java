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


import java.net.URI;

import com.nimbusds.oauth2.sdk.id.State;
import junit.framework.TestCase;


/**
 * Tests the authorisation response class.
 */
public class AuthorizationResponseTest extends TestCase {


	// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/147/authorizationrequestparse-final-uri-uri
	public void testParseWithEncodedEqualsChar()
		throws Exception {

		URI redirectURI = URI.create("https://example.com/in");

		AuthorizationCode code = new AuthorizationCode("===code===");
		State state = new State("===state===");

		AuthorizationResponse response = new AuthorizationSuccessResponse(redirectURI, code, null, state, ResponseMode.QUERY);

		URI uri = response.toURI();

		response = AuthorizationResponse.parse(uri);

		assertEquals(state, response.getState());

		AuthorizationSuccessResponse successResponse = (AuthorizationSuccessResponse)response;

		assertEquals(code, successResponse.getAuthorizationCode());
		assertNull(successResponse.getAccessToken());
	}
	
	
	public void testToSuccessResponse()
		throws Exception {
		
		AuthorizationCode code = new AuthorizationCode();
		State state = new State();
		AuthorizationSuccessResponse successResponse = new AuthorizationSuccessResponse(URI.create("https://example.com/in"), code, null, state, ResponseMode.QUERY);
		
		URI uri = successResponse.toURI();
		
		successResponse = AuthorizationResponse.parse(uri).toSuccessResponse();
		
		assertEquals(code, successResponse.getAuthorizationCode());
		assertEquals(state, successResponse.getState());
	}
	
	
	public void testToErrorResponse()
		throws Exception {
		
		State state = new State();
		
		AuthorizationErrorResponse errorResponse = new AuthorizationErrorResponse(URI.create("https://example.com/in"), OAuth2Error.ACCESS_DENIED, state, ResponseMode.QUERY);
		
		URI uri = errorResponse.toURI();
		
		errorResponse = AuthorizationResponse.parse(uri).toErrorResponse();
		
		assertEquals(OAuth2Error.ACCESS_DENIED, errorResponse.getErrorObject());
		assertEquals(state, errorResponse.getState());
	}
}
