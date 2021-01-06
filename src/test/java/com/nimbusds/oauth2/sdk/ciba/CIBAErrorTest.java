/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk.ciba;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;


public class CIBAErrorTest extends TestCase {


	public void testConstants() {
		
		assertEquals("expired_login_hint_token", CIBAError.EXPIRED_LOGIN_HINT_TOKEN.getCode());
		assertEquals("Expired login_hint_token", CIBAError.EXPIRED_LOGIN_HINT_TOKEN.getDescription());
		assertNull(CIBAError.EXPIRED_LOGIN_HINT_TOKEN.getURI());
		assertEquals(HTTPResponse.SC_BAD_REQUEST, CIBAError.EXPIRED_LOGIN_HINT_TOKEN.getHTTPStatusCode());
		
		assertEquals("unknown_user_id", CIBAError.UNKNOWN_USER_ID.getCode());
		assertEquals("Unknown user ID", CIBAError.UNKNOWN_USER_ID.getDescription());
		assertNull(CIBAError.UNKNOWN_USER_ID.getURI());
		assertEquals(HTTPResponse.SC_BAD_REQUEST, CIBAError.UNKNOWN_USER_ID.getHTTPStatusCode());
		
		assertEquals("missing_user_code", CIBAError.MISSING_USER_CODE.getCode());
		assertEquals("Required user_code is missing", CIBAError.MISSING_USER_CODE.getDescription());
		assertNull(CIBAError.MISSING_USER_CODE.getURI());
		assertEquals(HTTPResponse.SC_BAD_REQUEST, CIBAError.MISSING_USER_CODE.getHTTPStatusCode());
		
		assertEquals("invalid_user_code", CIBAError.INVALID_USER_CODE.getCode());
		assertEquals("Invalid user_code", CIBAError.INVALID_USER_CODE.getDescription());
		assertNull(CIBAError.INVALID_USER_CODE.getURI());
		assertEquals(HTTPResponse.SC_BAD_REQUEST, CIBAError.INVALID_USER_CODE.getHTTPStatusCode());
		
		assertEquals("invalid_binding_message", CIBAError.INVALID_BINDING_MESSAGE.getCode());
		assertEquals("Invalid or unacceptable binding_message", CIBAError.INVALID_BINDING_MESSAGE.getDescription());
		assertNull(CIBAError.INVALID_BINDING_MESSAGE.getURI());
		assertEquals(HTTPResponse.SC_BAD_REQUEST, CIBAError.INVALID_BINDING_MESSAGE.getHTTPStatusCode());
		
		// push specific errors
		assertEquals("expired_token", CIBAError.EXPIRED_TOKEN.getCode());
		assertEquals("The auth_req_id has expired", CIBAError.EXPIRED_TOKEN.getDescription());
		assertNull(CIBAError.EXPIRED_TOKEN.getURI());
		assertEquals(0, CIBAError.EXPIRED_TOKEN.getHTTPStatusCode());
		
		assertEquals("transaction_failed", CIBAError.TRANSACTION_FAILED.getCode());
		assertEquals("The transaction failed due to an unexpected condition", CIBAError.TRANSACTION_FAILED.getDescription());
		assertNull(CIBAError.TRANSACTION_FAILED.getURI());
		assertEquals(0, CIBAError.TRANSACTION_FAILED.getHTTPStatusCode());
	}
}
