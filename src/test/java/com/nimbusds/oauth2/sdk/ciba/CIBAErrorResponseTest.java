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
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


public class CIBAErrorResponseTest extends TestCase {
	
	
	public void testStandardErrors() {
		
		// General OAuth
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(OAuth2Error.INVALID_REQUEST));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(OAuth2Error.INVALID_SCOPE));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(OAuth2Error.INVALID_CLIENT));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(OAuth2Error.UNAUTHORIZED_CLIENT));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(OAuth2Error.ACCESS_DENIED));
		
		// CIBA specific
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(CIBAError.EXPIRED_LOGIN_HINT_TOKEN));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(CIBAError.UNKNOWN_USER_ID));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(CIBAError.MISSING_USER_CODE));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(CIBAError.INVALID_USER_CODE));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(CIBAError.INVALID_BINDING_MESSAGE));
		
		assertEquals(10, CIBAErrorResponse.getStandardErrors().size());
	}
	
	
	public void testConstructParseLifeCycle() {
		
		CIBAErrorResponse errorResponse = new CIBAErrorResponse(CIBAError.EXPIRED_LOGIN_HINT_TOKEN);
		assertFalse(errorResponse.indicatesSuccess());
		assertEquals(CIBAError.EXPIRED_LOGIN_HINT_TOKEN, errorResponse.getErrorObject());
		
		JSONObject jsonObject = errorResponse.toJSONObject();
		assertEquals(jsonObject, CIBAError.EXPIRED_LOGIN_HINT_TOKEN.toJSONObject());
		
		HTTPResponse httpResponse = errorResponse.toHTTPResponse();
		assertEquals(400, httpResponse.getStatusCode());
		assertEquals(ContentType.APPLICATION_JSON, httpResponse.getEntityContentType());
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());
		assertEquals(3, httpResponse.getHeaderMap().size());
		assertEquals(jsonObject.toJSONString(), httpResponse.getContent());
	}
	
	
	public void testParseNoErrorCode() throws ParseException {
		
		HTTPResponse httpResponse = new HTTPResponse(400);
		
		CIBAErrorResponse errorResponse = CIBAErrorResponse.parse(httpResponse);
		assertNull(errorResponse.getErrorObject().getCode());
		assertNull(errorResponse.getErrorObject().getDescription());
		assertNull(errorResponse.getErrorObject().getURI());
		assertEquals(400, errorResponse.getErrorObject().getHTTPStatusCode());
	}
	
	
	public void testParse_reject200() {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		
		try {
			CIBAErrorResponse.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected HTTP status code, must not be 200 (OK)", e.getMessage());
		}
	}
}
