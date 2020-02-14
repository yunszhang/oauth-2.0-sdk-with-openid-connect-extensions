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

package com.nimbusds.openid.connect.sdk.federation.policy.operations;


import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.federation.policy.language.OperationName;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;


public class ValueOperationTest extends TestCase {
	
	
	public void testBooleanParam() {
		
		ValueOperation valueOperation = new ValueOperation();
		assertEquals(new OperationName("value"), valueOperation.getOperationName());
		valueOperation.configure(true);
		assertTrue(valueOperation.getBooleanConfiguration());
		
		assertTrue((Boolean) valueOperation.apply(null));
		assertTrue((Boolean) valueOperation.apply(true));
		assertTrue((Boolean) valueOperation.apply(false));
	}
	

	public void testStringParam() {
		
		ValueOperation valueOperation = new ValueOperation();
		assertEquals(new OperationName("value"), valueOperation.getOperationName());
		String stringParam = "support@federation.example.com";
		valueOperation.configure(stringParam);
		assertEquals(stringParam, valueOperation.getStringConfiguration());
		
		assertEquals(stringParam, valueOperation.apply(null));
		assertEquals(stringParam, valueOperation.apply("abc"));
	}
	

	public void testStringListParam() {
		
		ValueOperation valueOperation = new ValueOperation();
		assertEquals(new OperationName("value"), valueOperation.getOperationName());
		List<String> stringListParam = Arrays.asList("support@federation.example.com", "admin@federation.example.com");
		valueOperation.configure(stringListParam);
		assertEquals(stringListParam, valueOperation.getStringListConfiguration());
		
		assertEquals(stringListParam, valueOperation.apply(null));
		assertEquals(stringListParam, valueOperation.apply(Collections.singletonList("abc")));
	}
	
	
	public void testIllegalState() {
		
		try {
			new ValueOperation().apply(null);
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The policy is not initialized", e.getMessage());
		}
	}
	
	
	public void testParseBooleanParam() throws ParseException {
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.parseConfiguration((Object)true);
		assertTrue(valueOperation.getBooleanConfiguration());
	}
	
	
	public void testParseStringParam() throws ParseException {
		
		ValueOperation valueOperation = new ValueOperation();
		String stringParam = "support@federation.example.com";
		valueOperation.parseConfiguration((Object)stringParam);
		assertEquals(stringParam, valueOperation.getStringConfiguration());
	}
	
	
	public void testParseStringListParam() throws ParseException {
		
		ValueOperation valueOperation = new ValueOperation();
		List<String> stringListParam = Arrays.asList("support@federation.example.com", "admin@federation.example.com");
		valueOperation.parseConfiguration((Object)stringListParam);
		assertEquals(stringListParam, valueOperation.getStringListConfiguration());
	}
	
	
	public void testMerge_boolean() throws PolicyViolationException {
	
		ValueOperation o1 = new ValueOperation();
		o1.configure(true);
		
		ValueOperation o2 = new ValueOperation();
		o2.configure(true);
		
		assertTrue(((ValueOperation)o1.merge(o2)).getBooleanConfiguration());
		
		ValueOperation o3 = new ValueOperation();
		o3.configure(false);
		
		try {
			o1.merge(o3);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Value mismatch", e.getMessage());
		}
	}
	
	
	public void testMerge_string() throws PolicyViolationException {
	
		ValueOperation o1 = new ValueOperation();
		o1.configure("a");
		
		ValueOperation o2 = new ValueOperation();
		o2.configure("a");
		
		assertEquals("a", ((ValueOperation)o1.merge(o2)).getStringConfiguration());
		
		ValueOperation o3 = new ValueOperation();
		o3.configure("b");
		
		try {
			o1.merge(o3);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Value mismatch", e.getMessage());
		}
	}
	
	
	public void testMerge_stringList() throws PolicyViolationException {
	
		ValueOperation o1 = new ValueOperation();
		o1.configure(Arrays.asList("a", "b"));
		
		ValueOperation o2 = new ValueOperation();
		o2.configure(Arrays.asList("a", "b"));
		
		assertEquals(Arrays.asList("a", "b"), ((ValueOperation)o1.merge(o2)).getStringListConfiguration());
		
		ValueOperation o3 = new ValueOperation();
		o3.configure(Arrays.asList("c", "d"));
		
		try {
			o1.merge(o3);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Value mismatch", e.getMessage());
		}
	}
}
