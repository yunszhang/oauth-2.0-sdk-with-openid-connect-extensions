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

package com.nimbusds.oauth2.sdk.as;


import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Issuer;
import junit.framework.TestCase;


public class AuthorizationServerConfigurationRequestTest extends TestCase {
	
	
	public void testConstant() {
		
		assertEquals("/.well-known/oauth-authorization-server", AuthorizationServerConfigurationRequest.OAUTH_SERVER_WELL_KNOWN_PATH);
	}
	
	
	public void testConstruct() {
		
		Issuer issuer = new Issuer("https://c2id.com");
		
		AuthorizationServerConfigurationRequest request = new AuthorizationServerConfigurationRequest(issuer);
		
		assertEquals("https://c2id.com/.well-known/oauth-authorization-server", request.getEndpointURI().toString());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertEquals("https://c2id.com/.well-known/oauth-authorization-server", httpRequest.getURL().toString());
		assertTrue(httpRequest.getHeaderMap().isEmpty());
	}
	
	
	public void testConstructFromInvalidIssuer() {
		
		try {
			new AuthorizationServerConfigurationRequest(new Issuer("c2id.com")).toHTTPRequest();
			fail();
		} catch (SerializeException e) {
			assertEquals("URI is not absolute", e.getMessage());
		}
	}
}
