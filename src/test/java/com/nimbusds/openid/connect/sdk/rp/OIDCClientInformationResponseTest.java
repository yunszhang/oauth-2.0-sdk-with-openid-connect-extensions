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

package com.nimbusds.openid.connect.sdk.rp;


import java.net.URI;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


public class OIDCClientInformationResponseTest extends TestCase {
	
	
	
	private static OIDCClientInformation createSampleClientInformation() {
		
		ClientID id = new ClientID("123");
		Date issueDate = new Date(new Date().getTime() / 1000 * 1000);
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(URI.create("https://client.com/cb"));
		metadata.applyDefaults();
		Secret secret = new Secret();
		BearerAccessToken accessToken = new BearerAccessToken();
		URI uri = URI.create("https://c2id.com/client-reg/123");
		
		return new OIDCClientInformation(id, issueDate, metadata, secret, uri, accessToken);
	}
	
	
	private static void validate(OIDCClientInformation info, OIDCClientInformationResponse response) {
		
		assertTrue(response.indicatesSuccess());
		assertEquals(info.getID(), response.getClientInformation().getID());
		assertEquals(info.getIDIssueDate(), response.getClientInformation().getIDIssueDate());
		assertEquals(info.getMetadata().getRedirectionURI(), response.getClientInformation().getMetadata().getRedirectionURI());
		assertEquals(info.getSecret().getValue(), response.getClientInformation().getSecret().getValue());
		assertEquals(info.getRegistrationURI(), response.getClientInformation().getRegistrationURI());
		assertEquals(info.getRegistrationAccessToken().getValue(), response.getClientInformation().getRegistrationAccessToken().getValue());
	}


	public void testCycle_201()
		throws Exception {

		OIDCClientInformation info = createSampleClientInformation();

		boolean forNewClient = true;
		OIDCClientInformationResponse response = new OIDCClientInformationResponse(info, forNewClient);
		assertEquals(forNewClient, response.isForNewClient());

		assertTrue(response.indicatesSuccess());
		assertEquals(info, response.getOIDCClientInformation());
		assertEquals(info, response.getClientInformation());

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = OIDCClientInformationResponse.parse(httpResponse);
		assertEquals(forNewClient, response.isForNewClient());
		
		validate(info, response);
	}


	public void testCycle_200()
		throws Exception {

		OIDCClientInformation info = createSampleClientInformation();

		boolean forNewClient = false;
		OIDCClientInformationResponse response = new OIDCClientInformationResponse(info, forNewClient);
		assertEquals(forNewClient, response.isForNewClient());

		assertTrue(response.indicatesSuccess());
		assertEquals(info, response.getOIDCClientInformation());
		assertEquals(info, response.getClientInformation());

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = OIDCClientInformationResponse.parse(httpResponse);
		assertEquals(forNewClient, response.isForNewClient());
		
		validate(info, response);
	}
}
