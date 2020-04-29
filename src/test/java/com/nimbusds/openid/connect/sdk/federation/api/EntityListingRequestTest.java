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

package com.nimbusds.openid.connect.sdk.federation.api;


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;


public class EntityListingRequestTest extends TestCase {
	
	
	public void testLifecycle() throws Exception {
		
		for (EntityListingSpec listingSpec: EntityListingSpec.values()) {
			
			URI endpoint = new URI("https://openid.sunet.se/federation_api_endpoint");
			Issuer issuer = new Issuer("https://openid.sunet.se");
			EntityListingRequest request = new EntityListingRequest(endpoint, issuer, listingSpec);
			assertEquals(OperationType.LISTING, request.getOperationType());
			assertEquals(issuer, request.getIssuer());
			assertEquals(listingSpec, request.getListingSpec());
			
			Map<String, List<String>> params = request.toParameters();
			assertEquals(OperationType.LISTING.getValue(), MultivaluedMapUtils.getFirstValue(params, "operation"));
			assertEquals(issuer.getValue(), MultivaluedMapUtils.getFirstValue(params, "iss"));
			
			if (EntityListingSpec.ALL.equals(listingSpec)) {
				assertEquals(2, params.size());
			} else {
				if (EntityListingSpec.LEAF_ENTITIES_ONLY.equals(listingSpec)) {
					assertEquals("true", MultivaluedMapUtils.getFirstValue(params, "is_leaf"));
				}
				if (EntityListingSpec.INTERMEDIATES_ONLY.equals(listingSpec)) {
					assertEquals("false", MultivaluedMapUtils.getFirstValue(params, "is_leaf"));
				}
				assertEquals(3, params.size());
			}
			
			HTTPRequest httpRequest = request.toHTTPRequest();
			assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
			assertEquals(params, httpRequest.getQueryParameters());
			
			request = EntityListingRequest.parse(httpRequest);
			assertEquals(OperationType.LISTING, request.getOperationType());
			assertEquals(issuer, request.getIssuer());
			assertEquals(listingSpec, request.getListingSpec());
		}
	}
	
	
	public void testParse_notGET() throws MalformedURLException {
		
		try {
			EntityListingRequest.parse(new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/federation")));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP request method must be GET", e.getMessage());
		}
	}
	
	
	public void testParse_missingIssuer() throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.com/federation"));
		httpRequest.setQuery("operation=listing");
		
		try {
			EntityListingRequest.parse(httpRequest);
			fail();
		} catch (ParseException  e) {
			assertEquals("Missing iss (issuer) parameter", e.getMessage());
		}
	}
	
	
	public void testParse_operationMissing() throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.com/federation"));
		httpRequest.setQuery("iss=https://c2id.com/federation");
		
		try {
			EntityListingRequest.parse(httpRequest);
			fail();
		} catch (ParseException  e) {
			assertEquals("Missing operation type", e.getMessage());
		}
	}
	
	
	public void testParse_operationMismatch() throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.com/federation"));
		httpRequest.setQuery("operation=fetch&iss=https://c2id.com/federation");
		
		try {
			EntityListingRequest.parse(httpRequest);
			fail();
		} catch (ParseException  e) {
			assertEquals("The operation type must be listing", e.getMessage());
		}
	}
}
