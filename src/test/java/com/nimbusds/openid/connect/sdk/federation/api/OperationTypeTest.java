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

package com.nimbusds.openid.connect.sdk.federation.api;


import junit.framework.TestCase;


public class OperationTypeTest extends TestCase {
	
	
	public void testConstants() {
		assertEquals("fetch", OperationType.FETCH.getValue());
		assertEquals("resolve_metadata", OperationType.RESOLVE_METADATA.getValue());
		assertEquals("listing", OperationType.LISTING.getValue());
	}
	
	
	public void testConstructor() {
		
		String value = "some-operation";
		OperationType type = new OperationType(value);
		assertEquals(value, type.getValue());
		assertEquals(type, new OperationType(value));
		assertEquals(type.hashCode(), new OperationType(value).hashCode());
	}
	
	
	public void testInequality() {
		
		assertNotSame(new OperationType("a"), new OperationType("b"));
		assertNotSame(new OperationType("a").hashCode(), new OperationType("b").hashCode());
	}
}
