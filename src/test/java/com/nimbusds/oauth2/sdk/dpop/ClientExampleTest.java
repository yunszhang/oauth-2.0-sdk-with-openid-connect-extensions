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

package com.nimbusds.oauth2.sdk.dpop;


import java.net.URI;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;


public class ClientExampleTest extends TestCase {
	
	
	public void testExample() throws Exception {
		
		// Generate an EC key pair for signing the DPoP proofs with the
		// ES256 JWS algorithm. The OAuth 2.0 client should store this
		// key securely for the duration of its use.
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
			.keyID("1")
			.generate();
		
		// Create a DPoP proof factory for the EC key
		DPoPProofFactory proofFactory = new DefaultDPoPProofFactory(ecJWK, JWSAlgorithm.ES256);
		
		// Token request with DPoP for a public OAuth 2.0 client
		ClientID clientID = new ClientID("123");
		AuthorizationCode code = new AuthorizationCode("ohyahhaht0vee0ech7Kieleephieheif");
		URI redirectURI = new URI("https://example.com/callback");
		
		TokenRequest tokenRequest = new TokenRequest(
			new URI("https://demo.c2id.com/token"),
			clientID,
			new AuthorizationCodeGrant(code, redirectURI));
		
		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		
		// Generate a new DPoP proof for the token request
		SignedJWT proof = proofFactory.createDPoPJWT(
			httpRequest.getMethod().name(),
			httpRequest.getURI());
		httpRequest.setDPoP(proof);
		
		// Send the token request to the OAuth 2.0 server
		HTTPResponse httpResponse = httpRequest.send();
		
		TokenResponse tokenResponse = TokenResponse.parse(httpResponse);
		
		if (! tokenResponse.indicatesSuccess()) {
			// The token request failed
			System.err.println(tokenResponse.toErrorResponse().getErrorObject().getHTTPStatusCode());
			System.err.println(tokenResponse.toErrorResponse().getErrorObject().getCode());
			return;
		}
		
		Tokens tokens = tokenResponse.toSuccessResponse().getTokens();
		DPoPAccessToken dPoPAccessToken = tokens.getDPoPAccessToken();
		
		if (dPoPAccessToken == null) {
			// The access token is not of type DPoP. Depending on
			// its security policy the OAuth 2.0 client may choose
			// to abort here
			return;
		}
		
		// Access some DPoP aware resource with the token
		httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URI("https://api.example.com/accounts"));
		httpRequest.setAuthorization(dPoPAccessToken.toAuthorizationHeader());
		
		// Generate a new DPoP proof for the resource request
		proof = proofFactory.createDPoPJWT(
			httpRequest.getMethod().name(),
			httpRequest.getURI());
		httpRequest.setDPoP(proof);
		
		// Make the request
		httpRequest.send();
	}
}
