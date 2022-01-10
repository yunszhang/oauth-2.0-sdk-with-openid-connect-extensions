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


import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import javax.net.ssl.SSLSocketFactory;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.SelfSignedTLSClientAuthentication;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationResponseParser;


public class CIBAExampleTest {


	// CIBA example using the push token delivery mode
	// https://connect2id.com/products/nimbus-oauth-openid-connect-sdk/examples/openid-connect/ciba
	public void example()
		throws IOException, ParseException {
		
		// The OP / AS client registration endpoint
		URI clientRegEndpoint = URI.create("https://demo.c2id.com/clients/");
		
		// The initial registration access token
		BearerAccessToken clientRegToken = new BearerAccessToken("...");
		
		// Prepare the client metadata for CIBA with push token delivery,
		// the client is going to authenticate with a self-signed certificate (mTLS)
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setGrantTypes(Collections.singleton(GrantType.CIBA));
		clientMetadata.setJWKSetURI(URI.create("https://client.example.com/jwks.json"));
		clientMetadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);
		clientMetadata.setBackChannelTokenDeliveryMode(BackChannelTokenDeliveryMode.PUSH);
		clientMetadata.setBackChannelClientNotificationEndpoint(URI.create("https://client.example.com/ciba"));
		clientMetadata.setSupportsBackChannelUserCodeParam(true);
		clientMetadata.setScope(new Scope("openid", "email", "profile", "phone"));
		
		// Send the registration request
		HTTPResponse httpResponse = new OIDCClientRegistrationRequest(
			clientRegEndpoint, clientMetadata, clientRegToken)
			.toHTTPRequest()
			.send();
		
		ClientRegistrationResponse regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);
		
		if (! regResponse.indicatesSuccess()) {
			// Registration failed
			System.err.println(regResponse.toErrorResponse().getErrorObject());
			return;
		}
		
		// Successful registration
		OIDCClientInformation clientInfo = (OIDCClientInformation) regResponse.toSuccessResponse().getClientInformation();
//		System.out.println("Client ID: " + clientInfo.getID());
//		System.out.println("Client registration token: " + clientInfo.getRegistrationAccessToken());
//		System.out.println("Client metadata: " + clientInfo.getOIDCMetadata());
		
		
		// CIBA request
		
		// The OP / AS endpoint for back-channel authN and authZ requests
		URI cibaEndpoint = URI.create("https://demo.c2id.com/ciba");
		
		// Custom SSL factory for mTLS with the client's certificate
		SSLSocketFactory sslSocketFactory = null;
		ClientAuthentication clientAuth = new SelfSignedTLSClientAuthentication(clientInfo.getID(), sslSocketFactory);
		
		// Generate a bearer token to authorise the callback with the
		// token delivery at the client notification endpoint
		BearerAccessToken clientNotifyToken = new BearerAccessToken();
		
		// Make the CIBA request for an ID token, using a caller ID
		// as login hint
		HTTPResponse httpResponse1 = new CIBARequest.Builder(
			clientAuth,
			new Scope(OIDCScopeValue.OPENID))
			.endpointURI(cibaEndpoint)
			.clientNotificationToken(clientNotifyToken)
			.loginHint("+1-541-754-3010")
			.build()
			.toHTTPRequest()
			.send();
		
		CIBAResponse cibaResponse = CIBAResponse.parse(httpResponse);
		
		if (! cibaResponse.indicatesSuccess()) {
			// CIBA request failed
			System.err.println(cibaResponse.toErrorResponse().getErrorObject());
			return;
		}
		
		// Get the request acknowledgement
		CIBARequestAcknowledgement acknowledgement = cibaResponse.toRequestAcknowledgement();
		AuthRequestID cibaRequestID = acknowledgement.getAuthRequestID();
		int expiresInSeconds = acknowledgement.getExpiresIn();
		
		// Store the request context (with the client callback token
		// and other necessary details), keyed by the auth_req_id and
		// set to expire according to the received expires_in value in
		// seconds
		// ...
		
		// CIBA push token delivery
		HTTPRequest httpRequest = null;
		
		// Parse the callback
		CIBATokenDelivery tokenDelivery = CIBATokenDelivery.parse(httpRequest);
		
		cibaRequestID = acknowledgement.getAuthRequestID();
		
		// Get the request context previously stored by auth_req_id,
		// if expired abort
		// ...
		
		// Verify the callback access token with the stored one
		if (! clientNotifyToken.equals(tokenDelivery.getAccessToken())) {
			System.err.println("Invalid access token");
			return;
		}
		
		if (! tokenDelivery.indicatesSuccess()) {
			// Error delivered
			System.err.println(tokenDelivery.toErrorDelivery().getErrorObject());
			return;
		}
		
		// Get the delivered token(s)
		CIBATokenDelivery successfulTokenDelivery = tokenDelivery.toTokenDelivery();
		JWT idToken = successfulTokenDelivery.getOIDCTokens().getIDToken();
	}
}
