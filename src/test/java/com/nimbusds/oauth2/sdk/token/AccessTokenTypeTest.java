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

package com.nimbusds.oauth2.sdk.token;


import static org.junit.Assert.assertNotEquals;

import junit.framework.TestCase;


public class AccessTokenTypeTest extends TestCase {
	
	
	public void testTypeConstants() {
		
		assertEquals("Bearer", AccessTokenType.BEARER.getValue());
		assertEquals("DPoP", AccessTokenType.DPOP.getValue());
		assertEquals("mac", AccessTokenType.MAC.getValue());
		assertEquals("unknown", AccessTokenType.UNKNOWN.getValue());
	}


	public void testEquality() {
		
		assertEquals(new AccessTokenType("bearer"), new AccessTokenType("bearer"));
		assertEquals(new AccessTokenType("Bearer"), new AccessTokenType("Bearer"));
		assertEquals(new AccessTokenType("Bearer"), new AccessTokenType("bearer"));
		assertEquals(new AccessTokenType("bearer"), new AccessTokenType("BEARER"));
	}


	public void testInequality() {
		
		assertNotEquals(new AccessTokenType("bearer"), new AccessTokenType("mac"));
	}
}
