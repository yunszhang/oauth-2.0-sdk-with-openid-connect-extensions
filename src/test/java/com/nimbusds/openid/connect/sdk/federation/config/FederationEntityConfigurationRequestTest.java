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

package com.nimbusds.openid.connect.sdk.federation.config;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.WellKnownPathComposeStrategy;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.openid.connect.sdk.federation.config.FederationEntityConfigurationRequest;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


public class FederationEntityConfigurationRequestTest extends TestCase {
	
	
	public void testWellKnownConstant() {
		assertEquals("/.well-known/openid-federation", FederationEntityConfigurationRequest.OPENID_FEDERATION_ENTITY_WELL_KNOWN_PATH);
	}
	
	
	public void testConstruct() {
		
		EntityID entityID = new EntityID("https://op.c2id.com");
		FederationEntityConfigurationRequest request = new FederationEntityConfigurationRequest(entityID);
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertEquals("https://op.c2id.com/.well-known/openid-federation", httpRequest.getURL().toString());
	}
	
	
	public void testConstruct_defaultPostfix() {
		
		EntityID entityID = new EntityID("https://op.c2id.com/server");
		FederationEntityConfigurationRequest request = new FederationEntityConfigurationRequest(entityID);
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertEquals("https://op.c2id.com/server/.well-known/openid-federation", httpRequest.getURL().toString());
	}
	
	
	public void testConstruct_postfix() {
		
		EntityID entityID = new EntityID("https://op.c2id.com/server");
		FederationEntityConfigurationRequest request = new FederationEntityConfigurationRequest(entityID, WellKnownPathComposeStrategy.POSTFIX);
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertEquals("https://op.c2id.com/server/.well-known/openid-federation", httpRequest.getURL().toString());
	}
	
	
	public void testConstruct_infix() {
		
		EntityID entityID = new EntityID("https://op.c2id.com/server");
		FederationEntityConfigurationRequest request = new FederationEntityConfigurationRequest(entityID, WellKnownPathComposeStrategy.INFIX);
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertEquals("https://op.c2id.com/.well-known/openid-federation/server", httpRequest.getURL().toString());
	}
	
	
	public void testConstruct_trailingSlashInURI() {
		
		EntityID entityID = new EntityID("https://op.c2id.com/");
		FederationEntityConfigurationRequest request = new FederationEntityConfigurationRequest(entityID);
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertEquals("https://op.c2id.com/.well-known/openid-federation", httpRequest.getURL().toString());
	}
}
