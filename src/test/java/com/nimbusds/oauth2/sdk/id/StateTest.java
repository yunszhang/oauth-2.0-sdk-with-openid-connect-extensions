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


import static org.junit.Assert.assertNotEquals;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64;


public class StateTest extends TestCase {
	

	public void testValueConstructor() {

		String value = "abc";

		State state = new State(value);

		assertEquals(value, state.getValue());
		assertEquals(value, state.toString());
	}


	public void testEmptyValue() {

		try {
			new State("");

			fail("Failed to raise exception");
		
		} catch (IllegalArgumentException e) {

			// ok
		}
	}


	public void testEquality() {

		State s1 = new State("abc");

		State s2 = new State("abc");
		
		assertEquals(s1, s2);
	}


	public void testInequality() {

		State s1 = new State("abc");

		State s2 = new State("def");
		
		assertNotEquals(s1, s2);
	}


	public void testInequalityNull() {

		State s1 = new State("abc");
		
		assertNotEquals(null, s1);
	}


	public void testHashCode() {

		State s1 = new State("abc");

		State s2 = new State("abc");

		assertEquals(s1.hashCode(), s2.hashCode());
	}

	
	public void testGeneration() {
		
		State state = new State();
		
//		System.out.println("Random state (default byte length): " + state);
		
		assertEquals(Identifier.DEFAULT_BYTE_LENGTH, new Base64(state.toString()).decode().length);
	}
	
	
	public void testGenerationVarLength() {
	
		State state = new State(16);
		
//		System.out.println("Random state (16 byte length): " + state);
		
		assertEquals(16, new Base64(state.toString()).decode().length);
	}


	public void testJSONValue() {

		State state = new State("abc");

		String json = state.toJSONString();

//		System.out.println("\"state\":" + json);

		assertEquals("\"abc\"", json);
	}
}
