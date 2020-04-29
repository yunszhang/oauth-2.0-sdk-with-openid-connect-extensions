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

import com.nimbusds.oauth2.sdk.ParseException;


public class EntityIDConstraintTest extends TestCase {
	
	
	public void testParseExactMatch() throws ParseException {
		
		EntityIDConstraint c = EntityIDConstraint.parse("https://example.com/federation");
		
		assertTrue(c instanceof ExactMatchEntityIDConstraint);
		ExactMatchEntityIDConstraint exact = (ExactMatchEntityIDConstraint)c;
		assertEquals("https://example.com/federation", exact.toString());
	}
	
	
	public void testParseSubtreeMatch() throws ParseException {
		
		EntityIDConstraint c = EntityIDConstraint.parse("https://.example.com/federation");
		
		assertTrue(c instanceof SubtreeEntityIDConstraint);
		SubtreeEntityIDConstraint subtree = (SubtreeEntityIDConstraint) c;
		assertEquals("https://.example.com/federation", subtree.toString());
	}
	
	
	public void testParseException_scheme() {
		
		try {
			EntityIDConstraint.parse("ftp://example.com");
			fail();
		} catch (ParseException e) {
			assertEquals("The entity ID must be an URI with https or http scheme", e.getMessage());
		}
	}
	
	
	public void testParseException_noHost() {
		
		try {
			EntityIDConstraint.parse("https:///");
			fail();
		} catch (ParseException e) {
			assertEquals("The entity ID must be an URI with authority (hostname)", e.getMessage());
		}
	}
}
