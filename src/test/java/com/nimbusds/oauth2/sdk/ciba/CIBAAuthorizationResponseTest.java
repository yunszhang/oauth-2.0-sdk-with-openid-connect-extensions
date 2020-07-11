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

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

public class CIBAAuthorizationResponseTest extends TestCase {

	public void testToALcknowledgementSuccessResponse() {
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("auth_req_id",  "1c266114-a1be-4252-8ad1-04986c5b9ac1");
		jsonObject.put("expires_in",  "120");
		jsonObject.put("interval",  "2");
		try {
			
			CIBAAuthorizationResponse response = CIBAAuthorizationResponse.parse(jsonObject);

			boolean isInstanceOf = (response instanceof CIBASuccessfulAcknowledgementResponse);
			assertTrue(isInstanceOf);
		} catch (ParseException e) {
			fail();
		}
	}

	public void testToSuccessfulTokenResponse() {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("access_token",  "G5kXH2wHvUra0sHlDy1iTkDJgsgUO1bN");
		jsonObject.put("token_type",  "Bearer");
		jsonObject.put("expires_in",  "120");
		jsonObject.put("id_token",  "eyJhbGciOiJSUzI1NiIs");
		jsonObject.put("refresh_token",  "4bwc0ESC_IAhflf-ACC_vjD_ltc11ne-8gFPfA2Kx16");
		try {

			CIBAAuthorizationResponse response = CIBAAuthorizationResponse.parse(jsonObject);

			boolean isInstanceOf = (response instanceof CIBASuccessfulTokenResponse);
			assertTrue(isInstanceOf);
		} catch (ParseException e) {
			fail();
		}
	}

	public void testToErrorResponse() {

		JSONObject jsonObject = OAuth2Error.INVALID_REQUEST.toJSONObject();
		try {

			CIBAAuthorizationResponse response = CIBAAuthorizationResponse.parse(jsonObject);

			boolean isInstanceOf = (response instanceof CIBAAuthorizationErrorResponse);
			assertTrue(isInstanceOf);
		} catch (ParseException e) {
			fail();
		}

		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);

	
		try {
			httpResponse.setContentType("application/json");
			httpResponse.setContent(jsonObject.toString());
			
			CIBAAuthorizationResponse response = CIBAAuthorizationResponse.parse(httpResponse);

			boolean isInstanceOf = (response instanceof CIBAAuthorizationErrorResponse);
			assertTrue(isInstanceOf);
		} catch (ParseException e) {
			fail();
		}
	}

	public void testParseAccessToken() {

		JSONObject jsonObject =  OAuth2Error.INVALID_REQUEST.toJSONObject();
		try {

			CIBAAuthorizationResponse response = CIBAAuthorizationResponse.parse(jsonObject);

			boolean isInstanceOf = (response instanceof CIBAAuthorizationErrorResponse);
			assertTrue(isInstanceOf);
			jsonObject = new JSONObject();
			jsonObject.put("auth_req_id",  "1c266114-a1be-4252-8ad1-04986c5b9ac1");
			jsonObject.put("expires_in",  "120");
			jsonObject.put("interval",  "2");
			response = CIBAAuthorizationResponse.parse(jsonObject);

			isInstanceOf = (response instanceof CIBASuccessfulAcknowledgementResponse);
			assertTrue(isInstanceOf);
		} catch (ParseException e) {
			fail();
		}
	}

	public void testParseOK() {
		JSONObject jsonObject =  OAuth2Error.INVALID_REQUEST.toJSONObject();
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);
		try {

			CIBAAuthorizationResponse response = CIBAAuthorizationResponse.parse(httpResponse);

			boolean isInstanceOf = (response instanceof CIBAAuthorizationErrorResponse);
			assertTrue(isInstanceOf);

			jsonObject.put("auth_req_id",  "1c266114-a1be-4252-8ad1-04986c5b9ac1");
			jsonObject.put("expires_in",  "120");
			jsonObject.put("interval",  "2");
			
			httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
			httpResponse.setContent(jsonObject.toJSONString());
			httpResponse.setContentType("application/json");
			
			response = CIBAAuthorizationResponse.parse(httpResponse);

			isInstanceOf = (response instanceof CIBASuccessfulAcknowledgementResponse);
			assertTrue(isInstanceOf);
		} catch (ParseException e) {
			fail();
		}
	}

}
