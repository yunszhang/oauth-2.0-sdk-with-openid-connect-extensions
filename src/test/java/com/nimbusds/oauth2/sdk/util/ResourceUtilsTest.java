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

package com.nimbusds.oauth2.sdk.util;


import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;


public class ResourceUtilsTest extends TestCase {
	
	
	public void testIsLegalResourceURI_true() {
		
		assertTrue(ResourceUtils.isLegalResourceURI(null));
		assertTrue(ResourceUtils.isLegalResourceURI(URI.create("https://rs1.com")));
		assertTrue(ResourceUtils.isLegalResourceURI(URI.create("https://rs1.com/")));
		assertTrue(ResourceUtils.isLegalResourceURI(URI.create("https://rs1.com:8080/")));
		assertTrue(ResourceUtils.isLegalResourceURI(URI.create("https://rs1.com/api")));
		assertTrue(ResourceUtils.isLegalResourceURI(URI.create("https:///api/v1")));
		assertTrue(ResourceUtils.isLegalResourceURI(URI.create("https://rs1.com/api?query")));
		assertTrue(ResourceUtils.isLegalResourceURI(URI.create("resource://rs1.com/api/v1")));
		assertTrue(ResourceUtils.isLegalResourceURI(URI.create("urn:uuid:33336dcd-a239-444a-90ae-76d381c3e6d5")));
	}
	
	
	public void testIsLegalResourceURI_false() {
		
		assertFalse(ResourceUtils.isLegalResourceURI(URI.create("https://rs1.com/api#fragment")));
		assertFalse(ResourceUtils.isLegalResourceURI(URI.create("/api#fragment")));
	}
	
	
	public void testDeprecatedIsValidResourceURI_true() {
		
		assertTrue(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com")));
		assertTrue(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com/")));
		assertTrue(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com:8080/")));
		assertTrue(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com/api")));
		assertTrue(ResourceUtils.isValidResourceURI(URI.create("https:///api/v1")));
		assertTrue(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com/api?query")));
		assertTrue(ResourceUtils.isValidResourceURI(URI.create("resource://rs1.com/api/v1")));
		assertTrue(ResourceUtils.isValidResourceURI(URI.create("urn:uuid:33336dcd-a239-444a-90ae-76d381c3e6d5")));
	}
	
	
	public void testDeprecatedIsValidResourceURI_false() {
		
		assertFalse(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com/api#fragment")));
		assertFalse(ResourceUtils.isValidResourceURI(URI.create("/api#fragment")));
	}
	
	
	public void testParseResourceURIs_null() throws ParseException {
		
		assertNull(ResourceUtils.parseResourceURIs(null));
	}
	
	
	public void testParseResourceURIs_empty() throws ParseException {
		
		assertNull(ResourceUtils.parseResourceURIs(new LinkedList<String>()));
	}
	
	
	public void testParseResourceURIs_oneURI() throws ParseException {
		
		URI uri = URI.create("https://rs.example.com/api");
		
		assertEquals(
			Collections.singletonList(uri),
			ResourceUtils.parseResourceURIs(Collections.singletonList(uri.toString()))
		);
	}
	
	
	public void testParseResourceURIs_twoURIs() throws ParseException {
		
		URI uri1 = URI.create("https://rs1.example.com/api");
		URI uri2 = URI.create("https://rs2.example.com/api");
		
		assertEquals(
			Arrays.asList(uri1, uri2),
			ResourceUtils.parseResourceURIs(Arrays.asList(uri1.toString(), uri2.toString()))
		);
	}
	
	
	public void testParseResourceURIs_nullElement() throws ParseException {
		
		URI uri1 = URI.create("https://rs1.example.com/api");
		URI uri2 = URI.create("https://rs2.example.com/api");
		
		assertEquals(
			Arrays.asList(uri1, uri2),
			ResourceUtils.parseResourceURIs(Arrays.asList(uri1.toString(), null, uri2.toString()))
		);
	}
	
	
	public void testParseResourceURIs_illegalURI() {
		
		try {
			ResourceUtils.parseResourceURIs(Collections.singletonList("%"));
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal resource parameter: Must be an absolute URI and with no query or fragment", e.getMessage());
		}
	}
	
	
	public void testParseResourceURIs_relativeURI() {
		
		try {
			ResourceUtils.parseResourceURIs(Collections.singletonList("/api/"));
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal resource parameter: Must be an absolute URI and with no query or fragment", e.getMessage());
		}
	}
	
	
	public void testParseResourceURIs_uriWithFragment() {
		
		try {
			ResourceUtils.parseResourceURIs(Collections.singletonList("https://rs.example.com/api#fragment"));
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal resource parameter: Must be an absolute URI and with no query or fragment", e.getMessage());
		}
	}
}
