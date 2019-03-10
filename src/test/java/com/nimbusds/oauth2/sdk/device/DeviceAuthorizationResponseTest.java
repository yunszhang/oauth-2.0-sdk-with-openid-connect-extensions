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

package com.nimbusds.oauth2.sdk.device;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;

public class DeviceAuthorizationResponseTest extends TestCase {

	public void testRegisteredParameters() {

		assertTrue(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames().contains("device_code"));
		assertTrue(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames().contains("user_code"));
		assertTrue(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames()
		                .contains("verification_uri"));
		assertTrue(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames()
		                .contains("verification_uri_complete"));
		assertTrue(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames().contains("expires_in"));
		assertTrue(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames().contains("interval"));
		assertEquals(6, DeviceAuthorizationSuccessResponse.getRegisteredParameterNames().size());
	}


	public void testMinimalSuccess() throws Exception {

		DeviceCode deviceCode = new DeviceCode();
		UserCode userCode = new UserCode();
		URI verificationUri = new URI("https://c2id.com/devauthz/");
		long lifetime = 1800;

		DeviceAuthorizationSuccessResponse resp = new DeviceAuthorizationSuccessResponse(deviceCode, userCode,
		                verificationUri, lifetime);

		assertEquals(deviceCode, resp.getDeviceCode());
		assertEquals(userCode, resp.getUserCode());
		assertEquals(verificationUri, resp.getVerificationUri());
		assertEquals(lifetime, resp.getLifetime());

		assertEquals(null, resp.getVerificationUriComplete());
		assertEquals(5, resp.getInterval());

		assertTrue(resp.getCustomParameters().isEmpty());

		HTTPResponse httpResp = resp.toHTTPResponse();
		JSONObject params = httpResp.getContentAsJSONObject();
		assertEquals(deviceCode.getValue(), params.getAsString("device_code"));
		assertEquals(userCode.getValue(), params.getAsString("user_code"));
		assertEquals(verificationUri.toString(), params.getAsString("verification_uri"));
		assertFalse(params.containsKey("verification_uri_complete"));
		assertEquals(lifetime, params.getAsNumber("expires_in"));
		assertEquals(5L, params.getAsNumber("interval"));
		assertEquals(5, params.size());

		resp = DeviceAuthorizationResponse.parse(httpResp).toSuccessResponse();

		assertEquals(deviceCode, resp.getDeviceCode());
		assertEquals(userCode, resp.getUserCode());
		assertEquals(verificationUri, resp.getVerificationUri());
		assertEquals(lifetime, resp.getLifetime());

		assertEquals(null, resp.getVerificationUriComplete());
		assertEquals(5, resp.getInterval());

		assertTrue(resp.getCustomParameters().isEmpty());
	}


	public void testFull() throws Exception {

		DeviceCode deviceCode = new DeviceCode();
		UserCode userCode = new UserCode();
		URI verificationUri = new URI("https://c2id.com/devauthz/");
		URI verificationUriComplete = new URI("https://c2id.com/devauthz/complete");
		long lifetime = 3600;
		long interval = 10;

		Map<String, Object> customParams = new HashMap<>();
		customParams.put("x", "100");
		customParams.put("y", "200");
		customParams.put("z", "300");

		DeviceAuthorizationSuccessResponse resp = new DeviceAuthorizationSuccessResponse(deviceCode, userCode,
		                verificationUri, verificationUriComplete, lifetime, interval, customParams);

		assertEquals(deviceCode, resp.getDeviceCode());
		assertEquals(userCode, resp.getUserCode());
		assertEquals(verificationUri, resp.getVerificationUri());
		assertEquals(verificationUriComplete, resp.getVerificationUriComplete());
		assertEquals(lifetime, resp.getLifetime());
		assertEquals(interval, resp.getInterval());
		assertEquals("100", resp.getCustomParameters().get("x"));
		assertEquals("200", resp.getCustomParameters().get("y"));
		assertEquals("300", resp.getCustomParameters().get("z"));
		assertEquals(3, resp.getCustomParameters().size());

		HTTPResponse httpResp = resp.toHTTPResponse();
		JSONObject params = httpResp.getContentAsJSONObject();
		assertEquals(deviceCode.getValue(), params.getAsString("device_code"));
		assertEquals(userCode.getValue(), params.getAsString("user_code"));
		assertEquals(verificationUri.toString(), params.getAsString("verification_uri"));
		assertEquals(verificationUriComplete.toString(), params.getAsString("verification_uri_complete"));
		assertEquals(lifetime, params.getAsNumber("expires_in"));
		assertEquals(interval, params.getAsNumber("interval"));
		assertEquals("100", params.getAsString("x"));
		assertEquals("200", params.getAsString("y"));
		assertEquals("300", params.getAsString("z"));
		assertEquals(9, params.size());

		resp = DeviceAuthorizationResponse.parse(httpResp).toSuccessResponse();

		assertEquals(deviceCode, resp.getDeviceCode());
		assertEquals(userCode, resp.getUserCode());
		assertEquals(verificationUri, resp.getVerificationUri());
		assertEquals(verificationUriComplete, resp.getVerificationUriComplete());
		assertEquals(lifetime, resp.getLifetime());
		assertEquals(interval, resp.getInterval());
		assertEquals("100", resp.getCustomParameters().get("x"));
		assertEquals("200", resp.getCustomParameters().get("y"));
		assertEquals("300", resp.getCustomParameters().get("z"));
		assertEquals(3, resp.getCustomParameters().size());
	}


	public void testToErrorResponse() throws Exception {

		DeviceAuthorizationErrorResponse response = new DeviceAuthorizationErrorResponse(
		                DeviceFlowError.AUTHORIZATION_PENDING);

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = DeviceAuthorizationResponse.parse(httpResponse).toErrorResponse();

		assertEquals(DeviceFlowError.AUTHORIZATION_PENDING, response.getErrorObject());
	}
}
