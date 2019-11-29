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

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.client.ClientRegistrationErrorResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;


public class OIDCClientRegistrationResponseParserTest extends TestCase {
	
	
	private static OIDCClientInformation createSampleOIDCClientInformation() {
		
		ClientID id = new ClientID("123");
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(URI.create("https://client.com/cb"));
		URI regURI = URI.create("https://c2id.com/client-reg/123");
		BearerAccessToken accessToken = new BearerAccessToken();
		metadata.setName("My app");
		metadata.applyDefaults();
		
		return new OIDCClientInformation(id, null, metadata, null, regURI, accessToken);
	}
	
	
	private static void validate(final OIDCClientInformation clientInfo, final OIDCClientInformationResponse response) {
		
		assertEquals(clientInfo.getID(), response.getOIDCClientInformation().getID());
		assertEquals(clientInfo.getMetadata().getName(), response.getOIDCClientInformation().getMetadata().getName());
		assertNull(response.getOIDCClientInformation().getSecret());
		assertNull(response.getOIDCClientInformation().getIDIssueDate());
		assertEquals(clientInfo.getRegistrationURI(), response.getOIDCClientInformation().getRegistrationURI());
		assertEquals(clientInfo.getRegistrationAccessToken().getValue(), response.getOIDCClientInformation().getRegistrationAccessToken().getValue());
	}


	public void testParseSuccess_201()
		throws Exception {

		OIDCClientInformation clientInfo = createSampleOIDCClientInformation();

		OIDCClientInformationResponse response = new OIDCClientInformationResponse(clientInfo, true);
		assertTrue(response.isForNewClient());

		assertTrue(response.indicatesSuccess());

		HTTPResponse httpResponse = response.toHTTPResponse();

		ClientRegistrationResponse regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

		assertTrue(regResponse.indicatesSuccess());
		response = (OIDCClientInformationResponse)regResponse;
		validate(clientInfo, response);
	}


	public void testParseSuccess_200()
		throws Exception {

		OIDCClientInformation clientInfo = createSampleOIDCClientInformation();

		OIDCClientInformationResponse response = new OIDCClientInformationResponse(clientInfo, false);
		assertFalse(response.isForNewClient());

		assertTrue(response.indicatesSuccess());

		HTTPResponse httpResponse = response.toHTTPResponse();

		ClientRegistrationResponse regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

		assertTrue(regResponse.indicatesSuccess());
		response = (OIDCClientInformationResponse)regResponse;
		validate(clientInfo, response);
	}


	public void testParseError()
		throws Exception {

		ClientRegistrationErrorResponse response = new ClientRegistrationErrorResponse(BearerTokenError.INVALID_TOKEN);
		assertFalse(response.indicatesSuccess());

		HTTPResponse httpResponse = response.toHTTPResponse();

		ClientRegistrationResponse regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

		assertFalse(regResponse.indicatesSuccess());
		response = (ClientRegistrationErrorResponse)regResponse;
		assertEquals(BearerTokenError.INVALID_TOKEN.getCode(), response.getErrorObject().getCode());
	}
}
