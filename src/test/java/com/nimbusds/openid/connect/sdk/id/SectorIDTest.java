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

package com.nimbusds.openid.connect.sdk.id;


import java.net.URI;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Identifier;


public class SectorIDTest extends TestCase {
	
	
	public void testEnsureHTTPScheme_pass() {
		
		SectorID.ensureHTTPScheme(URI.create("https://example.com/callbacks.json"));
	}
	
	
	public void testEnsureHTTPScheme_fail() {
		
		String msg = null;
		try {
			SectorID.ensureHTTPScheme(URI.create("http://example.com/callbacks.json"));
			fail();
		} catch (IllegalArgumentException e) {
			msg = e.getMessage();
		}
		assertEquals("The URI must have a https scheme", msg);
		
		try {
			SectorID.ensureHTTPScheme(URI.create("urn:c2id:sector_id:cae3Otae"));
			fail();
		} catch (IllegalArgumentException e) {
			msg = e.getMessage();
		}
		assertEquals("The URI must have a https scheme", msg);
	}
	
	
	public void testEnsureHostComponent_pass() {
		
		assertEquals("example.com", SectorID.ensureHostComponent(URI.create("https://example.com/callback")));
	}
	
	
	public void testEnsureHostComponent_fail() {
		
		String msg = null;
		try {
			SectorID.ensureHostComponent(URI.create("https:///callback"));
			fail();
		} catch (IllegalArgumentException e) {
			msg = e.getMessage();
		}
		assertEquals("The URI must contain a host component", msg);
		
		try {
			SectorID.ensureHostComponent(URI.create("urn:c2id:sector_id:cae3Otae"));
			fail();
		} catch (IllegalArgumentException e) {
			msg = e.getMessage();
		}
		assertEquals("The URI must contain a host component", msg);
	}
	
	
	public void testStringConstructor() {

		String host = "example.com";
		SectorID sectorID = new SectorID(host);
		assertEquals(host, sectorID.getValue());
	}
	
	
	public void testURIConstructor_https() {

		URI url = URI.create("https://example.com/sector.json");
		SectorID sectorID = new SectorID(url);
		assertEquals("example.com", sectorID.getValue());
	}
	
	
	public void testURIConstructor_http() {

		URI url = URI.create("http://example.com/sector.json");
		SectorID sectorID = new SectorID(url);
		assertEquals("example.com", sectorID.getValue());
	}
	
	
	public void testURIConstructor_missingHost() {

		try {
			new SectorID(URI.create("https:///path/a/b/c"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The URI must contain a host component", e.getMessage());
		}
	}
	
	
	public void testAudienceConstructor() {
		
		Audience audience = new Audience("3f7951a7-0aa4-43cd-835a-1d3f6d024c24");
		SectorID sectorID = new SectorID(audience);
		assertEquals(audience.getValue(), sectorID.getValue());
	}
	
	
	public void testIdentifierConstructor() {
		
		Identifier identifier = new Identifier("cae3Otae");
		SectorID sectorID = new SectorID(identifier);
		assertEquals(identifier.getValue(), sectorID.getValue());
	}
	
	
	public void testEqualityAndHashCode() {
		
		SectorID a = new SectorID("https://rp.example.com/a/b/c");
		SectorID b = new SectorID("https://rp.example.com/a/b/c");
		
		assertEquals(a, b);
		assertEquals(a.hashCode(), b.hashCode());
	}
	
	
	public void testInequality() {
		
		SectorID a = new SectorID("https://rp.example.com/b");
		SectorID b = new SectorID("https://rp.example.com/a");
		
		assertNotSame(a, b);
		assertNotSame(a.hashCode(), b.hashCode());
	}
}
