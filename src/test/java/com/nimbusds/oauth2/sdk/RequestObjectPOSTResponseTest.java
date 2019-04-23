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
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;


public class RequestObjectPOSTResponseTest extends TestCase {
	
	
	public void testParseSuccess()
		throws Exception {
		
		Issuer issuer = new Issuer("https://c2id.com");
		Audience audience = new Audience("123");
		URI requestURI = URI.create("urn:requests:aashoo1Ooj6ahc5C");
		long expTs = DateUtils.toSecondsSinceEpoch(new Date());
		Date exp = DateUtils.fromSecondsSinceEpoch(expTs);
		
		RequestObjectPOSTSuccessResponse response = new RequestObjectPOSTSuccessResponse(issuer, audience, requestURI, exp);
		
		assertEquals(issuer, response.getIssuer());
		assertEquals(audience, response.getAudience());
		assertEquals(requestURI, response.getRequestURI());
		assertEquals(exp, response.getExpirationTime());
		
		assertTrue(response.indicatesSuccess());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		
		response = RequestObjectPOSTResponse.parse(httpResponse).toSuccessResponse();
		
		assertEquals(issuer, response.getIssuer());
		assertEquals(audience, response.getAudience());
		assertEquals(requestURI, response.getRequestURI());
		assertEquals(exp, response.getExpirationTime());
		
		assertTrue(response.indicatesSuccess());
	}
	
	
	public void testParseError()
		throws Exception {
		
		RequestObjectPOSTErrorResponse errorResponse = new RequestObjectPOSTErrorResponse(HTTPResponse.SC_UNAUTHORIZED);
		
		assertEquals(HTTPResponse.SC_UNAUTHORIZED, errorResponse.getHTTPStatusCode());
		
		assertNull(errorResponse.getErrorObject().getCode());
		assertNull(errorResponse.getErrorObject().getDescription());
		assertEquals(HTTPResponse.SC_UNAUTHORIZED, errorResponse.getErrorObject().getHTTPStatusCode());
		
		HTTPResponse httpResponse = errorResponse.toHTTPResponse();
		
		errorResponse = RequestObjectPOSTResponse.parse(httpResponse).toErrorResponse();
		
		assertEquals(HTTPResponse.SC_UNAUTHORIZED, errorResponse.getHTTPStatusCode());
		
		assertNull(errorResponse.getErrorObject().getCode());
		assertNull(errorResponse.getErrorObject().getDescription());
		assertEquals(HTTPResponse.SC_UNAUTHORIZED, errorResponse.getErrorObject().getHTTPStatusCode());
	}
}
