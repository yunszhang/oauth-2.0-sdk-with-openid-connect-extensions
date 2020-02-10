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


import junit.framework.TestCase;


public class EntityIDTest extends TestCase {
	
	
	public void testConstructor() {
		
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
			assertEquals("The entity identifier must be an URI: Illegal character in path at index 1: a b c", e.getMessage());
		}
	}
}
