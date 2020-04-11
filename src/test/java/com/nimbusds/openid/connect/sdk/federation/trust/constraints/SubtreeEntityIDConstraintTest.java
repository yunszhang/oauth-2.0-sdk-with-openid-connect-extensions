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

package com.nimbusds.openid.connect.sdk.federation.trust.constraints;


import junit.framework.TestCase;

import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


public class SubtreeEntityIDConstraintTest extends TestCase {
	
	
	public void testPatternsMatch() {
		
		assertTrue(new SubtreeEntityIDConstraint("https://.example.com").matches(new EntityID("https://my.example.com")));
		assertTrue(new SubtreeEntityIDConstraint("https://.example.com:8080").matches(new EntityID("https://my.example.com:8080")));
		assertTrue(new SubtreeEntityIDConstraint("https://.example.com/some/path").matches(new EntityID("https://my.example.com/some/path")));
		
		assertTrue(new SubtreeEntityIDConstraint("https://.example.com").matches(new EntityID("https://abc.my.example.com")));
		assertTrue(new SubtreeEntityIDConstraint("https://.example.com:8080").matches(new EntityID("https://abc.my.example.com:8080")));
		assertTrue(new SubtreeEntityIDConstraint("https://.example.com/some/path").matches(new EntityID("https://abc.my.example.com/some/path")));
		
		assertTrue(new SubtreeEntityIDConstraint("http://.example.com").matches(new EntityID("http://my.example.com")));
		assertTrue(new SubtreeEntityIDConstraint("http://.example.com:8080").matches(new EntityID("http://my.example.com:8080")));
		assertTrue(new SubtreeEntityIDConstraint("http://.example.com/some/path").matches(new EntityID("http://my.example.com/some/path")));
	}
	
	
	public void testPatternsNoMatch() {
		
		assertFalse(new SubtreeEntityIDConstraint("https://.example.com").matches(new EntityID("https://example.com")));
		assertFalse(new SubtreeEntityIDConstraint("https://.example.com").matches(new EntityID("https://example.org")));
		assertFalse(new SubtreeEntityIDConstraint("https://.example.com").matches(new EntityID("https://example.com:8080")));
		assertFalse(new SubtreeEntityIDConstraint("https://.example.com").matches(new EntityID("https://example.com:8080/some/path")));
		assertFalse(new SubtreeEntityIDConstraint("https://.example.com").matches(new EntityID("https://example.com/some/path")));
		assertFalse(new SubtreeEntityIDConstraint("https://.example.com").matches(new EntityID("http://my.example.com")));
	}
	
	
	public void testSchemaMustBeHTTPS_HTTP() {
		
		try {
			new SubtreeEntityIDConstraint("ftp://example.com");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The entity ID pattern must be an URI with https or http scheme", e.getMessage());
		}
	}
	
	
	public void testHostMustStartWithDot() {
		
		try {
			new SubtreeEntityIDConstraint("https://example.com");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The host part of the entity ID pattern must start with dot (.)", e.getMessage());
		}
	}
}
