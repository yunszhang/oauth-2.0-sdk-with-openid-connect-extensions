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

package secevent.sdk.claims;


import junit.framework.TestCase;

import com.nimbusds.secevent.sdk.claims.TXN;


public class TXNTest extends TestCase {
	
	
	public void testConstructor() {
		
		String value = "abc";
		
		TXN txn = new TXN(value);
		
		assertEquals(value, txn.getValue());
	}
	
	
	public void testEquality() {
		
		assertTrue(new TXN("abc").equals(new TXN("abc")));
	}
	
	
	public void testInEquality() {
		
		assertFalse(new TXN("abc").equals(new TXN("ABC")));
		assertFalse(new TXN("abc").equals(new TXN("123")));
	}
}
