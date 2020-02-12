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
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.federation.policy.language.OperationName;


public class DefaultOperationTest extends TestCase {
	
	
	public void testBooleanParam_true() {
		
		DefaultOperation valueOperation = new DefaultOperation();
		assertEquals(new OperationName("default"), valueOperation.getOperationName());
		valueOperation.configure(true);
		assertTrue(valueOperation.getBooleanConfiguration());
		
		assertTrue((Boolean) valueOperation.apply(null));
		assertTrue((Boolean) valueOperation.apply(true));
		assertFalse((Boolean) valueOperation.apply(false));
	}
	
	
	public void testBooleanParam_false() {
		
		DefaultOperation valueOperation = new DefaultOperation();
		assertEquals(new OperationName("default"), valueOperation.getOperationName());
		valueOperation.configure(false);
		assertFalse(valueOperation.getBooleanConfiguration());
		
		assertFalse((Boolean) valueOperation.apply(null));
		assertTrue((Boolean) valueOperation.apply(true));
		assertFalse((Boolean) valueOperation.apply(false));
	}
	

	public void testStringParam() {
		
		DefaultOperation valueOperation = new DefaultOperation();
		assertEquals(new OperationName("default"), valueOperation.getOperationName());
		String stringParam = "support@federation.example.com";
		valueOperation.configure(stringParam);
		assertEquals(stringParam, valueOperation.getStringConfiguration());
		
		assertEquals(stringParam, valueOperation.apply(null));
		assertEquals("admin@example.com", valueOperation.apply("admin@example.com"));
	}
	

	public void testStringListParam() {
		
		DefaultOperation valueOperation = new DefaultOperation();
		assertEquals(new OperationName("default"), valueOperation.getOperationName());
		List<String> stringListParam = Arrays.asList("support@federation.example.com", "admin@federation.example.com");
		valueOperation.configure(stringListParam);
		assertEquals(stringListParam, valueOperation.getStringListConfiguration());
		
		assertEquals(stringListParam, valueOperation.apply(null));
		assertEquals(Arrays.asList("support@example.com", "admin@example.com"), valueOperation.apply(Arrays.asList("support@example.com", "admin@example.com")));
	}
	
	
	public void testIllegalState() {
		
		try {
			new DefaultOperation().apply(null);
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The policy is not initialized", e.getMessage());
		}
	}
	
	
	public void testParseBooleanConfiguration()
		throws ParseException {
		
		DefaultOperation valueOperation = new DefaultOperation();
		valueOperation.parseConfiguration((Object)true);
		assertTrue(valueOperation.getBooleanConfiguration());
	}
	
	
	public void testParseStringConfiguration()
		throws ParseException {
		
		DefaultOperation valueOperation = new DefaultOperation();
		valueOperation.parseConfiguration((Object)"support@federation.example.com");
		assertEquals("support@federation.example.com", valueOperation.getStringConfiguration());
	}
	
	
	public void testParseStringListConfiguration()
		throws ParseException {
		
		DefaultOperation valueOperation = new DefaultOperation();
		List<String> stringListParam = Arrays.asList("support@federation.example.com", "admin@federation.example.com");
		valueOperation.parseConfiguration((Object)stringListParam);
		assertEquals(stringListParam, valueOperation.getStringListConfiguration());
	}
}
