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
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.dpop.verifiers.*;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;


public class DPoPExamples extends TestCase {
	
	
	public void _testClientExample() throws Exception {
		
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
	
	
	public void _testProtectedResourceExample() throws URISyntaxException {
		
		// The accepted DPoP proof JWS algorithms
		Set<JWSAlgorithm> acceptedAlgs = new HashSet<>(
			Arrays.asList(
				JWSAlgorithm.RS256,
				JWSAlgorithm.PS256,
				JWSAlgorithm.ES256));
		
		// The max accepted age of the DPoP proof JWTs
		long proofMaxAgeSeconds = 60;
		
		// DPoP single use checker, caches the DPoP proof JWT jti claims
		long cachePurgeIntervalSeconds = 600;
		SingleUseChecker<Map.Entry<DPoPIssuer, JWTID>> singleUseChecker =
			new DefaultDPoPSingleUseChecker(
				proofMaxAgeSeconds,
				cachePurgeIntervalSeconds);
		
		// Create the DPoP proof and access token binding verifier,
		// the class is thread-safe
		DPoPProtectedResourceRequestVerifier verifier =
			new DPoPProtectedResourceRequestVerifier(
				acceptedAlgs,
				proofMaxAgeSeconds,
				singleUseChecker);
		
		// Verify some request
		
		// The HTTP request method and URL
		String httpMethod = "GET";
		URI httpURI = new URI("https://api.example.com/accounts");
		
		// The DPoP proof, obtained from the HTTP DPoP header
		SignedJWT dPoPProof = null;
		
		// The DPoP access token, obtained from the HTTP Authorization header
		DPoPAccessToken accessToken = null;
		
		// The DPoP proof issuer, typically the client ID obtained from the
		// access token introspection
		DPoPIssuer dPoPIssuer = new DPoPIssuer(new ClientID("123"));
		
		// The JWK SHA-256 thumbprint confirmation, obtained from the
		// access token introspection
		JWKThumbprintConfirmation cnf = null;
		
		try {
			verifier.verify(httpMethod, httpURI, dPoPIssuer, dPoPProof, accessToken, cnf);
		} catch (InvalidDPoPProofException e) {
			System.err.println("Invalid DPoP proof: " + e.getMessage());
			return;
		} catch (AccessTokenValidationException e) {
			System.err.println("Invalid access token binding: " + e.getMessage());
			return;
		} catch (JOSEException e) {
			System.err.println("Internal error: " + e.getMessage());
			return;
		}
		
		// The request processing can proceed
	}
	
	
	public void _testTokenIntrospection() throws Exception {
		
		// Parse the token introspection response
		HTTPResponse httpResponse = null;
		TokenIntrospectionResponse response = TokenIntrospectionResponse.parse(httpResponse);
		
		if (! response.indicatesSuccess()) {
			// The introspection request failed
			System.err.println(response.toErrorResponse().getErrorObject().getHTTPStatusCode());
			System.err.println(response.toErrorResponse().getErrorObject().getCode());
			return;
		}
		
		TokenIntrospectionSuccessResponse tokenDetails = response.toSuccessResponse();
		
		if (! tokenDetails.isActive()) {
			System.out.println("Invalid / expired access token");
			return;
		}

		// Get the JWK SHA-256 thumbprint confirmation, found in the
		// cnf.jkt parameter, for use in the DPoPProtectedResourceRequestVerifier
		JWKThumbprintConfirmation cnf = tokenDetails.getJWKThumbprintConfirmation();
		
		if (cnf == null) {
			System.out.println("The token is not DPoP bound");
			return;
		}
		
		// Continue processing
	}
	
	
	public void _testExtractCnfFromJWT() throws Exception {
		
		JWTClaimsSet tokenClaims = null;
		
		JWKThumbprintConfirmation cnf = JWKThumbprintConfirmation.parse(tokenClaims);
		
		if (cnf == null) {
			System.out.println("The token is not DPoP bound");
			return;
		}
		
		// Continue processing
	}
}
