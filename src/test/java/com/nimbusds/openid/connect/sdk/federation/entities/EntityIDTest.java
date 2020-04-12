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

package com.nimbusds.openid.connect.sdk.federation.entities;


import java.net.URI;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;


public class EntityIDTest extends TestCase {
	
	
	public void testURIConstructor() {
		
		URI uri = URI.create("https://c2id.com");
		EntityID entityID = new EntityID(uri);
		assertEquals(uri.toString(), entityID.getValue());
		assertEquals(uri, entityID.toURI());
	}
	
	
	public void testStringConstructor() {
		
		String value = "https://c2id.com";
		
		EntityID id = new EntityID(value);
		assertEquals(value, id.getValue());
		assertEquals(value, id.toURI().toString());
		
		assertEquals(id, new EntityID(value));
		assertEquals(id.hashCode(), new EntityID(value).hashCode());
		
		assertNotSame(id, new EntityID("https://op.example.com"));
	}
	
	
	public void testNotURI() {
		
		try {
			new EntityID("a b c");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The entity ID must be an URI: Illegal character in path at index 1: a b c", e.getMessage());
		}
	}
	
	
	public void testURISchemeNotHTTPS_HTTP() {
		
		try {
			new EntityID("ftp://example.com");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The entity ID must be an URI with https or http scheme", e.getMessage());
		}
	}
	
	
	public void testURISchemeMissingAuthority() {
		
		try {
			new EntityID("https:///");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The entity ID must be an URI with authority (hostname)", e.getMessage());
		}
	}
	
	
	public void testParseFromStringNotURI() {
		
		try {
			EntityID.parse("a b c");
			fail();
		} catch (ParseException e) {
			assertEquals("The entity ID must be an URI: Illegal character in path at index 1: a b c", e.getMessage());
		}
	}
	
	
	public void testParseFromString() throws ParseException {
		
		String value = "https://c2id.com";
		
		assertEquals(value, EntityID.parse(value).getValue());
	}
	
	
	public void testParseFromIssuer() throws ParseException {
		
		String value = "https://c2id.com";
		
		assertEquals(value, EntityID.parse(new Issuer(value)).getValue());
	}
	
	
	public void testParseFromSubject() throws ParseException {
		
		String value = "https://c2id.com";
		
		assertEquals(value, EntityID.parse(new Subject(value)).getValue());
	}
}
