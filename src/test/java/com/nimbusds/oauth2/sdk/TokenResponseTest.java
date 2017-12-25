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


import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import junit.framework.TestCase;


public class TokenResponseTest extends TestCase {
	
	
	public void testToSuccessResponse()
		throws Exception {
		
		Tokens tokens = new Tokens(new BearerAccessToken(), new RefreshToken());
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse(tokens);
		
		HTTPResponse httpResponse = accessTokenResponse.toHTTPResponse();
		
		accessTokenResponse = TokenResponse.parse(httpResponse).toSuccessResponse();
		
		assertEquals(tokens.getAccessToken(), accessTokenResponse.getTokens().getAccessToken());
		assertEquals(tokens.getRefreshToken(), accessTokenResponse.getTokens().getRefreshToken());
	}
	
	
	public void testToErrorResponse()
		throws Exception {
		
		TokenErrorResponse tokenErrorResponse = new TokenErrorResponse(BearerTokenError.INVALID_TOKEN);
		
		HTTPResponse httpResponse = tokenErrorResponse.toHTTPResponse();
		
		tokenErrorResponse = TokenResponse.parse(httpResponse).toErrorResponse();
		
		assertEquals(BearerTokenError.INVALID_TOKEN, tokenErrorResponse.getErrorObject());
	}
}
