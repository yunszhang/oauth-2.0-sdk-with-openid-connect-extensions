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

package com.nimbusds.oauth2.sdk.id;


import junit.framework.TestCase;


/**
 * Tests the client ID class.
 */
public class ClientIDTest extends TestCase {


	public void testIdentifierConstructor() {

		assertEquals("123", new ClientID(new Issuer("123")).getValue());
	}


	public void testEquality() {

		assertTrue(new ClientID("123").equals(new ClientID(new Issuer("123"))));
	}
}
