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

package com.nimbusds.oauth2.sdk.client;


import java.net.URI;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;


public class ClientRegistrationResponseTest extends TestCase {
	
	
	private static ClientInformation createSampleClientInformation() {
		
		ClientID clientID = new ClientID("123");
		Date iat = new Date();
		ClientMetadata metadata = new ClientMetadata();
		metadata.setRedirectionURI(URI.create("https://example.com/cb"));
		metadata.applyDefaults();
		Secret secret = new Secret();
		return new ClientInformation(clientID, iat, metadata, secret);
	}
	
	
	// for new client
	public void testToCreatedResponse()
		throws Exception {
		
		ClientInformation clientInfo = createSampleClientInformation();
		
		boolean forNewClient = true;
		ClientInformationResponse clientInfoResponse = new ClientInformationResponse(clientInfo, forNewClient);
		assertEquals(forNewClient, clientInfoResponse.isForNewClient());
		
		HTTPResponse httpResponse = clientInfoResponse.toHTTPResponse();
		assertEquals(HTTPResponse.SC_CREATED, httpResponse.getStatusCode());
		
		clientInfoResponse = ClientRegistrationResponse.parse(httpResponse).toSuccessResponse();
		assertEquals(forNewClient, clientInfoResponse.isForNewClient());
		
		assertEquals(clientInfo.getID(), clientInfoResponse.getClientInformation().getID());
		assertEquals(clientInfo.getMetadata().getRedirectionURI(), clientInfoResponse.getClientInformation().getMetadata().getRedirectionURI());
	}
	
	
	// for retrieved or updated client
	public void testToSuccessResponse()
		throws Exception {
		
		ClientInformation clientInfo = createSampleClientInformation();
		
		boolean forNewClient = false;
		ClientInformationResponse clientInfoResponse = new ClientInformationResponse(clientInfo, forNewClient);
		assertEquals(forNewClient, clientInfoResponse.isForNewClient());
		
		HTTPResponse httpResponse = clientInfoResponse.toHTTPResponse();
		assertEquals(HTTPResponse.SC_OK, httpResponse.getStatusCode());
		
		clientInfoResponse = ClientRegistrationResponse.parse(httpResponse).toSuccessResponse();
		assertEquals(forNewClient, clientInfoResponse.isForNewClient());
		
		assertEquals(clientInfo.getID(), clientInfoResponse.getClientInformation().getID());
		assertEquals(clientInfo.getMetadata().getRedirectionURI(), clientInfoResponse.getClientInformation().getMetadata().getRedirectionURI());
	}
	
	
	public void testToErrorResponse()
		throws Exception {
		
		ClientRegistrationErrorResponse clientRegErrorResponse = new ClientRegistrationErrorResponse(OAuth2Error.INVALID_REQUEST);
		
		HTTPResponse httpResponse = clientRegErrorResponse.toHTTPResponse();
		
		clientRegErrorResponse = ClientRegistrationResponse.parse(httpResponse).toErrorResponse();
		
		assertEquals(OAuth2Error.INVALID_REQUEST, clientRegErrorResponse.getErrorObject());
	}
}
