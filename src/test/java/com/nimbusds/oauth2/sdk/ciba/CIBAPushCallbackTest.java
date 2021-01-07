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


import java.net.URI;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;


public class CIBAPushCallbackTest extends TestCase {
	
	
	private static final URI ENDPOINT = URI.create("https://client.example.com/ciba");
	
	private static final BearerAccessToken CLIENT_NOTIFICATION_TOKEN = new BearerAccessToken();
	
	private static final AuthRequestID AUTH_REQUEST_ID = new AuthRequestID();
	
	private static final AccessToken ACCESS_TOKEN = new BearerAccessToken(16, 120, new Scope("openid", "email"));
	
	
	public void testParseTokenDelivery()
		throws ParseException {
		
		Tokens tokens = new Tokens(ACCESS_TOKEN, null);
		
		CIBAPushCallback pushCallback = new CIBATokenDelivery(
			ENDPOINT,
			CLIENT_NOTIFICATION_TOKEN,
			AUTH_REQUEST_ID,
			tokens);
		
		HTTPRequest httpRequest = pushCallback.toHTTPRequest();
		
		pushCallback = CIBAPushCallback.parse(httpRequest);
		
		assertTrue(pushCallback.indicatesSuccess());
		
		CIBATokenDelivery tokenDelivery = pushCallback.toTokenDelivery();
		
		assertEquals(ENDPOINT, tokenDelivery.getEndpointURI());
		assertEquals(CLIENT_NOTIFICATION_TOKEN, tokenDelivery.getAccessToken());
		assertEquals(AUTH_REQUEST_ID, tokenDelivery.getAuthRequestID());
		assertEquals(tokens.toJSONObject(), tokenDelivery.getTokens().toJSONObject());
	}
	
	
	public void testParseErrorDelivery()
		throws ParseException {
		
		CIBAPushCallback pushCallback = new CIBAErrorDelivery(
			ENDPOINT,
			CLIENT_NOTIFICATION_TOKEN,
			AUTH_REQUEST_ID,
			CIBAError.EXPIRED_TOKEN);
		
		HTTPRequest httpRequest = pushCallback.toHTTPRequest();
		
		pushCallback = CIBAPushCallback.parse(httpRequest);
		
		assertFalse(pushCallback.indicatesSuccess());
		
		CIBAErrorDelivery errorDelivery = pushCallback.toErrorDelivery();
		
		assertEquals(ENDPOINT, errorDelivery.getEndpointURI());
		assertEquals(CLIENT_NOTIFICATION_TOKEN, errorDelivery.getAccessToken());
		assertEquals(AUTH_REQUEST_ID, errorDelivery.getAuthRequestID());
		assertEquals(CIBAError.EXPIRED_TOKEN, errorDelivery.getErrorObject());
	}
}
