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

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * Tests the OIDC client update request.
 */
public class OIDCClientUpdateRequestTest extends TestCase {


	public void testCycle()
		throws Exception {

		URI uri = new URI("https://c2id.com/client-reg/123");
		ClientID clientID = new ClientID("123");
		BearerAccessToken accessToken = new BearerAccessToken();
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/cb"));
		metadata.setName("My app");
		metadata.applyDefaults();
		Secret secret = new Secret();

		OIDCClientUpdateRequest request = new OIDCClientUpdateRequest(
			uri,
			clientID,
			accessToken,
			metadata,
			secret);

		assertEquals(uri, request.getEndpointURI());
		assertEquals(clientID, request.getClientID());
		assertEquals(accessToken, request.getAccessToken());
		assertEquals(metadata, request.getOIDCClientMetadata());
		assertEquals(metadata, request.getClientMetadata());
		assertEquals(secret, request.getClientSecret());


		HTTPRequest httpRequest = request.toHTTPRequest();

		request = OIDCClientUpdateRequest.parse(httpRequest);

		assertEquals(uri.toString(), request.getEndpointURI().toString());
		assertEquals(clientID.getValue(), request.getClientID().getValue());
		assertEquals(accessToken.getValue(), request.getAccessToken().getValue());
		assertEquals("https://client.com/cb", request.getClientMetadata().getRedirectionURIs().iterator().next().toString());
		assertEquals("My app", request.getClientMetadata().getName());
		assertEquals(secret.getValue(), request.getClientSecret().getValue());
	}
}
