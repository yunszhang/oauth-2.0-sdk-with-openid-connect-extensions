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
import java.util.Arrays;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;


public class UserInfoRequestTest extends TestCase {
	
	
	private static final BearerAccessToken BEARER_ACCESS_TOKEN = new BearerAccessToken("Eabeeduphee3aiviehahreacaoNg2thu");
	
	private static final DPoPAccessToken DPOP_ACCESS_TOKEN = new DPoPAccessToken("jo4kahphoh1ath4INaochohLeeshaiyo");

	public void testMinimalConstructor()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/userinfo");
		
		for (AccessToken token: Arrays.asList(BEARER_ACCESS_TOKEN, DPOP_ACCESS_TOKEN)) {
			
			UserInfoRequest request = new UserInfoRequest(endpointURI, token);
			
			assertEquals(endpointURI, request.getEndpointURI());
			assertEquals(token, request.getAccessToken());
			assertEquals(HTTPRequest.Method.GET, request.getMethod());
			
			HTTPRequest httpRequest = request.toHTTPRequest();
			
			assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
			assertEquals(endpointURI, httpRequest.getURL().toURI());
			assertNull(httpRequest.getQuery());
			assertEquals(token.toAuthorizationHeader(), httpRequest.getAuthorization());
			
			request = UserInfoRequest.parse(httpRequest);
			
			assertEquals(endpointURI, request.getEndpointURI());
			assertEquals(token.getValue(), request.getAccessToken().getValue());
			assertEquals(HTTPRequest.Method.GET, request.getMethod());
		}
	}

	public void testFullConstructor_GET()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/userinfo");
		
		for (AccessToken token: Arrays.asList(BEARER_ACCESS_TOKEN, DPOP_ACCESS_TOKEN)) {
			
			UserInfoRequest request = new UserInfoRequest(endpointURI, HTTPRequest.Method.GET, token);
			
			assertEquals(endpointURI, request.getEndpointURI());
			assertEquals(token, request.getAccessToken());
			assertEquals(HTTPRequest.Method.GET, request.getMethod());
			
			HTTPRequest httpRequest = request.toHTTPRequest();
			
			assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
			assertEquals(endpointURI, httpRequest.getURL().toURI());
			assertNull(httpRequest.getQuery());
			assertEquals(token.toAuthorizationHeader(), httpRequest.getAuthorization());
			
			request = UserInfoRequest.parse(httpRequest);
			
			assertEquals(endpointURI, request.getEndpointURI());
			assertEquals(token.getValue(), request.getAccessToken().getValue());
			assertEquals(HTTPRequest.Method.GET, request.getMethod());
		}
	}


	public void testFullConstructor_POST()
		throws Exception {

		URI url = new URI("https://c2id.com/userinfo");
		
		for (AccessToken token: Arrays.asList(BEARER_ACCESS_TOKEN, DPOP_ACCESS_TOKEN)) {
			
			UserInfoRequest request = new UserInfoRequest(url, HTTPRequest.Method.POST, token);
			
			assertEquals(url, request.getEndpointURI());
			assertEquals(token, request.getAccessToken());
			assertEquals(HTTPRequest.Method.POST, request.getMethod());
			
			HTTPRequest httpRequest = request.toHTTPRequest();
			
			assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
			assertEquals(url, httpRequest.getURL().toURI());
			assertEquals("application/x-www-form-urlencoded; charset=UTF-8", httpRequest.getEntityContentType().toString());
			assertEquals("access_token=" + token.getValue(), httpRequest.getQuery());
			assertNull(httpRequest.getAuthorization());
			
			request = UserInfoRequest.parse(httpRequest);
			
			assertEquals(url, request.getEndpointURI());
			assertEquals(AccessTokenType.UNKNOWN, request.getAccessToken().getType());
			assertEquals(token.getValue(), request.getAccessToken().getValue());
			assertEquals(HTTPRequest.Method.POST, request.getMethod());
		}
	}
}
