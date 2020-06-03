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
import java.net.URISyntaxException;

import junit.framework.TestCase;


/**
 * Tests the URI utility methods.
 */
public class URIUtilsTest extends TestCase {


	public void testGetBaseURISame()
		throws URISyntaxException {

		URI uri = new URI("http://client.example.com:8080/endpoints/openid/connect/cb");

		URI baseURI = URIUtils.getBaseURI(uri);

		assertEquals("http://client.example.com:8080/endpoints/openid/connect/cb", baseURI.toString());
	}


	public void testGetBaseURITrim()
		throws URISyntaxException {

		URI uri = new URI("http://client.example.com:8080/endpoints/openid/connect/cb?param1=one&param2=two");

		URI baseURI = URIUtils.getBaseURI(uri);

		assertEquals("http://client.example.com:8080/endpoints/openid/connect/cb", baseURI.toString());
	}
	
	
	public void testRemoveTrailingSlash() {
		
		URI uri = URI.create("https://example.com/");
		
		assertEquals("https://example.com", URIUtils.removeTrailingSlash(uri).toString());
	}
	
	
	public void testRemoveTrailingSlash_notFound() {
		
		URI uri = URI.create("https://example.com");
		
		assertEquals("https://example.com", URIUtils.removeTrailingSlash(uri).toString());
	}
	
	
	public void testStripQueryString() {
		
		// Null safe
		assertNull(URIUtils.stripQueryString(null));
		
		URI out = URIUtils.stripQueryString(URI.create("https://client.example.com:8080/endpoints/openid/connect/cb?param1=one&param2=two#fragment"));
		assertEquals("https://client.example.com:8080/endpoints/openid/connect/cb#fragment", out.toString());
		
		out = URIUtils.stripQueryString(URI.create("https://c2id.com:8080/login?param1=one&param2=two"));
		assertEquals("https://c2id.com:8080/login", out.toString());
	}
	
	
	public void testPrependSlashIfMissing() {
		
		assertNull(URIUtils.prependLeadingSlashIfMissing(null));
		
		assertEquals("/", URIUtils.prependLeadingSlashIfMissing(""));
		assertEquals("/ ", URIUtils.prependLeadingSlashIfMissing(" "));
		assertEquals("/  ", URIUtils.prependLeadingSlashIfMissing("  "));
		
		assertEquals("/abc", URIUtils.prependLeadingSlashIfMissing("abc"));
		assertEquals("/abc/def", URIUtils.prependLeadingSlashIfMissing("abc/def"));
		
		assertEquals("/abc", URIUtils.prependLeadingSlashIfMissing("/abc"));
		assertEquals("/abc/def", URIUtils.prependLeadingSlashIfMissing("/abc/def"));
	}
	
	
	public void testStringLeadingSlashIfPresent() {
		
		assertNull(URIUtils.stripLeadingSlashIfPresent(null));
		
		assertEquals("", URIUtils.stripLeadingSlashIfPresent(""));
		assertEquals(" ", URIUtils.stripLeadingSlashIfPresent(" "));
		assertEquals("  ", URIUtils.stripLeadingSlashIfPresent("  "));
		
		assertEquals("", URIUtils.stripLeadingSlashIfPresent("/"));
		assertEquals(" ", URIUtils.stripLeadingSlashIfPresent("/ "));
		assertEquals("  ", URIUtils.stripLeadingSlashIfPresent("/  "));
		
		assertEquals("abc", URIUtils.stripLeadingSlashIfPresent("/abc"));
		assertEquals("abc/def", URIUtils.stripLeadingSlashIfPresent("/abc/def"));
		
		assertEquals("abc", URIUtils.stripLeadingSlashIfPresent("//abc"));
		assertEquals("abc/def", URIUtils.stripLeadingSlashIfPresent("//abc/def"));
		
		assertEquals("abc", URIUtils.stripLeadingSlashIfPresent("///abc"));
		assertEquals("abc/def", URIUtils.stripLeadingSlashIfPresent("///abc/def"));
		
		assertEquals("abc", URIUtils.stripLeadingSlashIfPresent("abc"));
		assertEquals("abc/def", URIUtils.stripLeadingSlashIfPresent("abc/def"));
	}
	
	
	public void testJoinPathComponents() {
		
		assertNull(URIUtils.joinPathComponents(null, null));
		
		assertEquals("/", URIUtils.joinPathComponents("/", "/"));
		assertEquals("/", URIUtils.joinPathComponents("/", null));
		assertEquals("/", URIUtils.joinPathComponents(null, "/"));
		
		assertEquals("/abc", URIUtils.joinPathComponents("/abc", ""));
		assertEquals("abc", URIUtils.joinPathComponents("abc", ""));
		
		assertEquals("def/", URIUtils.joinPathComponents("", "def/"));
		assertEquals("def", URIUtils.joinPathComponents("", "def"));
		
		assertEquals("/abc/def", URIUtils.joinPathComponents("/abc", "/def"));
		assertEquals("abc/def", URIUtils.joinPathComponents("abc", "/def"));
		assertEquals("/abc/def", URIUtils.joinPathComponents("/abc", "def"));
		assertEquals("abc/def", URIUtils.joinPathComponents("abc", "def"));
		
		assertEquals("/abc/def/ghi", URIUtils.joinPathComponents("/abc", "/def/ghi"));
		assertEquals("abc/def/ghi", URIUtils.joinPathComponents("abc", "/def/ghi"));
		assertEquals("/abc/def/ghi", URIUtils.joinPathComponents("/abc", "def/ghi"));
		assertEquals("abc/def/ghi", URIUtils.joinPathComponents("abc", "def/ghi"));
	}
	
	
	public void testPrependPath() {
	
		assertNull(URIUtils.prependPath(null, "/"));
		assertNull(URIUtils.prependPath(null, null));
		
		URI uri = URI.create("https://c2id.com/abc/def");
		
		assertEquals(uri, URIUtils.prependPath(uri, null));
		
		assertEquals(uri, URIUtils.prependPath(uri, ""));
		assertEquals(uri, URIUtils.prependPath(uri, " "));
		assertEquals(uri, URIUtils.prependPath(uri, "  "));
		assertEquals(uri, URIUtils.prependPath(uri, "   "));
		
		assertEquals(uri, URIUtils.prependPath(uri, "/"));
		
		assertEquals(
			URI.create("https://c2id.com/abc/def"),
			URIUtils.prependPath(uri, "/")
		);
		
		assertEquals(
			URI.create("https://c2id.com/xyz/abc/def"),
			URIUtils.prependPath(uri, "/xyz/")
		);
		
		assertEquals(
			URI.create("https://c2id.com/xyz/abc/def"),
			URIUtils.prependPath(uri, "/xyz")
		);
		
		assertEquals(
			URI.create("https://c2id.com/xyz/abc/def"),
			URIUtils.prependPath(uri, "xyz")
		);
		
		assertEquals(
			URI.create("https://c2id.com/.well-known/oauth-authorization-server/abc/def"),
			URIUtils.prependPath(uri, "/.well-known/oauth-authorization-server")
		);
		
		assertEquals(
			URI.create("https://c2id.com/.well-known/oauth-authorization-server/abc/def"),
			URIUtils.prependPath(uri, ".well-known/oauth-authorization-server")
		);
		
		// special cases
		
		
		assertEquals(
			URI.create("https://c2id.com/.well-known/oauth-authorization-server"),
			URIUtils.prependPath(URI.create("https://c2id.com"),
				"/.well-known/oauth-authorization-server")
		);
		assertEquals(
			URI.create("https://c2id.com/.well-known/oauth-authorization-server"),
			URIUtils.prependPath(URI.create("https://c2id.com/"),
				"/.well-known/oauth-authorization-server")
		);
	}
}
