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


public class SectorIDTest extends TestCase {
	

	public void testStringConstructor() {

		SectorID sectorID = new SectorID("example.com");
		assertEquals("example.com", sectorID.getValue());
	}


	public void testURIConstructor() {

		SectorID sectorID = new SectorID(URI.create("https://example.com"));
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


	public void testEnsureHTTPScheme() {

		try {
			SectorID.ensureHTTPScheme(URI.create("http://example.com/callbacks.json"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The URI must have a https scheme", e.getMessage());
		}
	}
	
	
	public void testAudienceConstructor() {
		
		Audience audience = new Audience("3f7951a7-0aa4-43cd-835a-1d3f6d024c24");
		SectorID sectorID = new SectorID(audience);
		assertEquals(audience.getValue(), sectorID.getValue());
	}
}
