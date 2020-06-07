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


public class OneOfOperationTest extends TestCase {
	
	
	public void testOneOf() throws PolicyViolationException {
		
		List<String> param = Arrays.asList("ES256", "ES384", "ES512");
		
		OneOfOperation operation = new OneOfOperation();
		assertEquals(new OperationName("one_of"), operation.getOperationName());
		operation.configure(param);
		assertEquals(param, operation.getStringListConfiguration());
		
		assertEquals("ES384", operation.apply("ES384"));
	}
	
	
	public void testOneOfNegative() {
		
		List<String> param = Arrays.asList("ES256", "ES384", "ES512");
		
		OneOfOperation operation = new OneOfOperation();
		assertEquals(new OperationName("one_of"), operation.getOperationName());
		operation.configure(param);
		assertEquals(param, operation.getStringListConfiguration());
		
		try {
			operation.apply("PS256");
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Value PS256 not in policy list: [ES256, ES384, ES512]", e.getMessage());
		}
	}
	
	
	public void testNotInit() throws PolicyViolationException {
		
		try {
			new OneOfOperation().apply(null);
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The policy is not initialized", e.getMessage());
		}
	}
	
	
	public void testParseConfiguration()
		throws ParseException {
		
		OneOfOperation operation = new OneOfOperation();
		List<String> param = Arrays.asList("ES256", "ES384", "ES512");
		operation.parseConfiguration((Object)param);
		assertEquals(param, operation.getStringListConfiguration());
		
		assertEquals(operation.getOperationName().getValue(), operation.toJSONObjectEntry().getKey());
		assertEquals(param, operation.toJSONObjectEntry().getValue());
	}
	
	
	public void testMerge() throws PolicyViolationException {
		
		List<String> p1 = Arrays.asList("ES256", "ES384", "ES512");
		List<String> p2 = Arrays.asList("ES256", "ES384", "ES512", "PS256", "PS384", "PS512");
		
		OneOfOperation o1 = new OneOfOperation();
		o1.configure(p1);
		OneOfOperation o2 = new OneOfOperation();
		o2.configure(p2);
		
		assertEquals(Arrays.asList("ES256", "ES384", "ES512"), ((OneOfOperation)o1.merge(o2)).getStringListConfiguration());
	}
	
	
	public void testMerge_noIntersection() throws PolicyViolationException {
		
		List<String> p1 = Arrays.asList("ES256", "ES384", "ES512");
		List<String> p2 = Arrays.asList("PS256", "PS384", "PS512");
		
		OneOfOperation o1 = new OneOfOperation();
		o1.configure(p1);
		OneOfOperation o2 = new OneOfOperation();
		o2.configure(p2);
		
		assertEquals(Collections.emptyList(), ((OneOfOperation)o1.merge(o2)).getStringListConfiguration());
	}
}
