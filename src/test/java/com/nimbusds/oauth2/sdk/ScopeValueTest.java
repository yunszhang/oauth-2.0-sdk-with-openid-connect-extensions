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

package com.nimbusds.oauth2.sdk;


import junit.framework.TestCase;


/**
 * Tests the scope token class.
 */
public class ScopeValueTest extends TestCase {


	public void testMinimalConstructor() {

		Scope.Value t = new Scope.Value("read");

		assertEquals("read", t.getValue());

		assertNull(t.getRequirement());
	}


	public void testFullConstructor() {

		Scope.Value t = new Scope.Value("write", Scope.Value.Requirement.OPTIONAL);

		assertEquals("write", t.getValue());

		assertEquals(Scope.Value.Requirement.OPTIONAL, t.getRequirement());
	}


	public void testEquality() {

		Scope.Value t1 = new Scope.Value("read");
		Scope.Value t2 = new Scope.Value("read");

		assertTrue(t1.equals(t2));
	}
}
