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

package com.nimbusds.oauth2.sdk.ciba;


import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


public class CIBAResponseTest extends TestCase {

	
	public void testParseRequestAcknowledgement()
		throws ParseException {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("auth_req_id",  "1c266114-a1be-4252-8ad1-04986c5b9ac1");
		jsonObject.put("expires_in",  120);
		jsonObject.put("interval",  2);
		httpResponse.setContent(jsonObject.toJSONString());
		
		CIBAResponse response = CIBAResponse.parse(httpResponse);
		
		CIBARequestAcknowledgement successResponse = response.toRequestAcknowledgement();
		
		assertEquals(new AuthRequestID("1c266114-a1be-4252-8ad1-04986c5b9ac1"), successResponse.getAuthRequestID());
		assertEquals(120, successResponse.getExpiresIn());
		assertEquals(2, successResponse.getMinWaitInterval().intValue());
	}
	

	public void testParseErrorResponse_asJSONObject()
		throws ParseException {
		
		CIBAResponse response = CIBAResponse.parse(OAuth2Error.INVALID_REQUEST.toJSONObject());
		CIBAErrorResponse errorResponse = response.toErrorResponse();
		assertEquals(OAuth2Error.INVALID_REQUEST, errorResponse.getErrorObject());
	}
	
	
	public void testParseErrorResponse_asHTTPResponse()
		throws ParseException {
		
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);
		httpResponse.setContentType("application/json");
		httpResponse.setContent(OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString());
		
		CIBAResponse response = CIBAResponse.parse(httpResponse);
		CIBAErrorResponse errorResponse = response.toErrorResponse();
		assertEquals(OAuth2Error.INVALID_REQUEST, errorResponse.getErrorObject());
	}
}
