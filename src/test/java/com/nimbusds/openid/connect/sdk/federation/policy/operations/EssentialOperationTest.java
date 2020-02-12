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


import java.util.Collections;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.federation.policy.language.OperationName;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;


public class EssentialOperationTest extends TestCase {
	
	
	public void testPolicyViolationException() {
		
		EssentialOperation operation = new EssentialOperation();
		assertEquals(new OperationName("essential"), operation.getOperationName());
		operation.configure(true);
		assertTrue(operation.getBooleanConfiguration());
		
		try {
			operation.apply(null);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Essential parameter not present", e.getMessage());
		}
	}
	
	
	public void testBooleanParam() throws PolicyViolationException {
		
		EssentialOperation operation = new EssentialOperation();
		assertEquals(new OperationName("essential"), operation.getOperationName());
		operation.configure(true);
		
		assertTrue((Boolean) operation.apply(true));
		assertFalse((Boolean) operation.apply(false));
	}
	

	public void testStringParam() throws PolicyViolationException {
		
		EssentialOperation operation = new EssentialOperation();
		assertEquals(new OperationName("essential"), operation.getOperationName());
		operation.configure(true);
		
		assertEquals("abc", operation.apply("abc"));
	}
	

	public void testStringListParam() throws PolicyViolationException {
		
		EssentialOperation operation = new EssentialOperation();
		assertEquals(new OperationName("essential"), operation.getOperationName());
		operation.configure(true);
		
		assertEquals(Collections.singletonList("abc"), operation.apply(Collections.singletonList("abc")));
	}
	
	
	public void testParseConfiguration()
		throws ParseException {
		
		EssentialOperation operation = new EssentialOperation();
		operation.parseConfiguration((Object)true);
		assertTrue(operation.getBooleanConfiguration());
	}
}
