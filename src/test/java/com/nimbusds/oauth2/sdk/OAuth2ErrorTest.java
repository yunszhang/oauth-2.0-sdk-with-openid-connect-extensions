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


import junit.framework.TestCase;


/**
 * Tests the OAuth 2.0 error constants.
 */
public class OAuth2ErrorTest extends TestCase {


	public void testHTTPStatusCodes() {

		assertEquals(403, OAuth2Error.ACCESS_DENIED.getHTTPStatusCode());
		assertEquals(401, OAuth2Error.INVALID_CLIENT.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.INVALID_GRANT.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.INVALID_REQUEST.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.INVALID_SCOPE.getHTTPStatusCode());
		assertEquals(500, OAuth2Error.SERVER_ERROR.getHTTPStatusCode());
		assertEquals(503, OAuth2Error.TEMPORARILY_UNAVAILABLE.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.UNAUTHORIZED_CLIENT.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.UNSUPPORTED_GRANT_TYPE.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.INVALID_RESOURCE.getHTTPStatusCode());
	}
	
	
	public void testInvalidResourceError() {
		
		assertEquals("invalid_resource", OAuth2Error.INVALID_RESOURCE.getCode());
		assertEquals("Invalid or unaccepted resource", OAuth2Error.INVALID_RESOURCE.getDescription());
		assertEquals(400, OAuth2Error.INVALID_RESOURCE.getHTTPStatusCode());
	}
}
