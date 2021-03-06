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
import java.util.List;
import java.util.Map;

import static net.jadler.Jadler.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class HTTPTokenRequestTest {
	
	
	@Before
	public void setUp() {
		initJadler();
	}
	
	
	@After
	public void tearDown() {
		closeJadler();
	}
	
	
	@Test
	public void testPOST()
		throws Exception {
		
		final AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), URI.create("https://example.com/cb"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://localhost:" + port() + "/token"), new ClientSecretBasic(new ClientID("123"), new Secret("secret")), codeGrant);
		
		BearerAccessToken token = new BearerAccessToken("xyz");
		AccessTokenResponse tokenResponse = new AccessTokenResponse(new Tokens(token, null));
		
		onRequest()
			.havingMethodEqualTo("POST")
			.havingPathEqualTo("/token")
			.havingHeaderEqualTo("Content-Type", ContentType.APPLICATION_URLENCODED.toString())
			.havingBody(new BaseMatcher<String>() {
				@Override
				public boolean matches(Object o) {
					Map<String,List<String>> postParams = URLUtils.parseParameters(o.toString());
					Map<String,List<String>> expectedPostParams = codeGrant.toParameters();
					for (Map.Entry<String,List<String>> exp: expectedPostParams.entrySet()) {
						if (! postParams.get(exp.getKey()).equals(exp.getValue()))
							return false;
					}
					return expectedPostParams.size() == postParams.size();
				}
				@Override
				public void describeTo(Description description) {
					
				}
			})
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(tokenResponse.toJSONObject().toJSONString());
		
		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		
		HTTPResponse httpResponse = httpRequest.send();
		
		assertEquals(200, httpResponse.getStatusCode());
		
		AccessTokenResponse receivedTokenResponse = AccessTokenResponse.parse(httpResponse);
		assertEquals(tokenResponse.getTokens().getBearerAccessToken(), receivedTokenResponse.getTokens().getBearerAccessToken());
		assertNull(receivedTokenResponse.getTokens().getRefreshToken());
	}
}
