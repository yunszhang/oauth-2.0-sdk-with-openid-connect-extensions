/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.assurance.evidences.attachment;


import junit.framework.TestCase;


public class HashAlgorithmTest extends TestCase {


	public void testConstants() {
		
		assertEquals("sha-256", HashAlgorithm.SHA_256.getValue());
		assertEquals("sha-384", HashAlgorithm.SHA_384.getValue());
		assertEquals("sha-512", HashAlgorithm.SHA_512.getValue());
	}
	
	
	public void testConstructor() {
	
		String name = "sha-256-128";
		HashAlgorithm alg = new HashAlgorithm(name);
		assertEquals(name, alg.getValue());
	}
	
	
	public void testNormalizeToLowerCase() {
		
		String name = "SHA-256-128";
		HashAlgorithm alg = new HashAlgorithm(name);
		assertEquals(name.toLowerCase(), alg.getValue());
	}
	
	
	
	public void testNotNull() {
		
		try {
			new HashAlgorithm(null);
			fail();
		} catch (NullPointerException e) {
			// ok
		}
	}
	
	
	public void testEquality() {
		
		assertEquals(HashAlgorithm.SHA_256, new HashAlgorithm("sha-256"));
		assertEquals(HashAlgorithm.SHA_256, new HashAlgorithm("SHA-256"));
	}
	
	
	public void testInequality() {
		
		assertNotSame(HashAlgorithm.SHA_256, new HashAlgorithm("sha-384"));
		assertNotSame(HashAlgorithm.SHA_256, new HashAlgorithm("SHA-384"));
	}
}
