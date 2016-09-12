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


/**
 * Tests the OIDC client registration response parser.
 */
public class OIDCClientRegistrationResponseParserTest extends TestCase {


	public void testParseSuccess()
		throws Exception {

		ClientID id = new ClientID("123");
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/cb"));
		URI regURI = new URI("https://c2id.com/client-reg/123");
		BearerAccessToken accessToken = new BearerAccessToken();
		metadata.setName("My app");
		metadata.applyDefaults();

		OIDCClientInformation clientInfo = new OIDCClientInformation(id, null, metadata, null, regURI, accessToken);

		OIDCClientInformationResponse response = new OIDCClientInformationResponse(clientInfo);

		assertTrue(response.indicatesSuccess());

		HTTPResponse httpResponse = response.toHTTPResponse();

		ClientRegistrationResponse regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

		assertTrue(regResponse.indicatesSuccess());
		response = (OIDCClientInformationResponse)regResponse;

		assertEquals(id, response.getOIDCClientInformation().getID());
		assertEquals("My app", response.getOIDCClientInformation().getMetadata().getName());
		assertNull(response.getOIDCClientInformation().getSecret());
		assertNull(response.getOIDCClientInformation().getIDIssueDate());
		assertEquals(regURI, response.getOIDCClientInformation().getRegistrationURI());
		assertEquals(accessToken.getValue(), response.getOIDCClientInformation().getRegistrationAccessToken().getValue());
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
