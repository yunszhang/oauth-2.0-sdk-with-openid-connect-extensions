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

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;


public class ClientInformationResponseTest extends TestCase {
	
	
	public void testLifeCycle() throws ParseException {
		
		
		ClientID clientID = new ClientID();
		Date iat = new Date();
		ClientMetadata metadata = new ClientMetadata();
		metadata.setRedirectionURI(URI.create("https://example.com/cb"));
		metadata.applyDefaults();
		Secret secret = new Secret();
		
		ClientInformation clientInfo = new ClientInformation(clientID, iat, metadata, secret);
		ClientInformationResponse response = new ClientInformationResponse(clientInfo);
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(201, httpResponse.getStatusCode());
		
		assertEquals(clientInfo.toJSONObject(), httpResponse.getContentAsJSONObject());
	}
}
