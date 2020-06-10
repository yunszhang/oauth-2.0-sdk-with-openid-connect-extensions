/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.registration;


import java.net.MalformedURLException;
import java.net.URI;

import static com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementTest.RSA_JWK;
import static com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementTest.createEntityStatementClaimsSet;

import junit.framework.TestCase;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;


public class ExplicitClientRegistrationRequestTest extends TestCase {
	
	
	public void testLifeCycle()
		throws Exception {
		
		EntityStatementClaimsSet claimsSet = createEntityStatementClaimsSet();
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, RSA_JWK);
		
		URI endpoint = URI.create("https://c2id.com/federation/clients");
		
		ExplicitClientRegistrationRequest request = new ExplicitClientRegistrationRequest(endpoint, entityStatement);
		
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(entityStatement, request.getEntityStatement());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(endpoint, httpRequest.getURI());
		assertEquals(endpoint.toURL(), httpRequest.getURL());
		assertEquals(ContentType.APPLICATION_JOSE, httpRequest.getEntityContentType());
		assertEquals(entityStatement.getSignedStatement().serialize(), httpRequest.getQuery());
		
		request = ExplicitClientRegistrationRequest.parse(httpRequest);
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(entityStatement.getSignedStatement().serialize(), request.getEntityStatement().getSignedStatement().getParsedString());
	}
	
	
	public void testParse_methodNotPOST()
		throws MalformedURLException {
		
		try {
			ExplicitClientRegistrationRequest.parse(new HTTPRequest(HTTPRequest.Method.GET, URI.create("https://c2id.com/federation/clients").toURL()));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP request method must be POST", e.getMessage());
		}
	}
	
	
	public void testParse_contentTypeHeaderMissing()
		throws Exception {
		
		EntityStatementClaimsSet claimsSet = createEntityStatementClaimsSet();
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, RSA_JWK);
		
		URI endpoint = URI.create("https://c2id.com/federation/clients");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpoint.toURL());
		httpRequest.setQuery(entityStatement.getSignedStatement().serialize());
		
		try {
			ExplicitClientRegistrationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing HTTP Content-Type header", e.getMessage());
		}
	}
	
	
	public void testParse_contentTypeHeaderNotJOSE()
		throws Exception {
		
		EntityStatementClaimsSet claimsSet = createEntityStatementClaimsSet();
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, RSA_JWK);
		
		URI endpoint = URI.create("https://c2id.com/federation/clients");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpoint.toURL());
		httpRequest.setEntityContentType(ContentType.APPLICATION_JWT);
		httpRequest.setQuery(entityStatement.getSignedStatement().serialize());
		
		try {
			ExplicitClientRegistrationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/jose; charset=UTF-8", e.getMessage());
		}
	}
	
	
	public void testParse_invalidSignedJWT()
		throws Exception {
		
		URI endpoint = URI.create("https://c2id.com/federation/clients");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpoint.toURL());
		httpRequest.setEntityContentType(ContentType.APPLICATION_JOSE);
		httpRequest.setQuery("not-a-jwt");
		
		try {
			ExplicitClientRegistrationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid entity statement: Invalid serialized unsecured/JWS/JWE object: Missing part delimiters", e.getMessage());
		}
	}
}
