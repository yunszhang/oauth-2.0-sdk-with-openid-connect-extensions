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

package com.nimbusds.openid.connect.sdk.federation.policy.operations;


import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;


public class DefaultPolicyOperationCombinationValidatorTest extends TestCase {
	
	
	public void testScopeExample() throws PolicyViolationException {
		// "scopes": {
		//        "subset_of": ["openid", "eduperson", "phone"],
		//        "superset_of": ["openid"],
		//        "default": ["openid", "eduperson"]}
		
		SubsetOfOperation subsetOfOperation = new SubsetOfOperation();
		subsetOfOperation.configure(Arrays.asList("openid", "eduperson", "phone"));
		
		SupersetOfOperation supersetOfOperation = new SupersetOfOperation();
		supersetOfOperation.configure(Collections.singletonList("openid"));
		
		DefaultOperation defaultOperation = new DefaultOperation();
		defaultOperation.configure(Arrays.asList("openid", "eduperson"));
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(subsetOfOperation);
		policyOperations.add(supersetOfOperation);
		policyOperations.add(defaultOperation);
		
		assertEquals(policyOperations, new DefaultPolicyOperationCombinationValidator().validate(policyOperations));
	}
	
	
	public void testDefaultAndValueCannotBeCombined() {
		// "scopes": {
		//        "default": ["openid", "eduperson"],
		//        "value": ["openid", "phone"]}
		
		DefaultOperation defaultOperation = new DefaultOperation();
		defaultOperation.configure(Arrays.asList("openid", "eduperson"));
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure(Arrays.asList("openid", "eduperson"));
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(defaultOperation);
		policyOperations.add(valueOperation);
		
		try {
			new DefaultPolicyOperationCombinationValidator().validate(policyOperations);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Policies default and value cannot be combined", e.getMessage());
		}
	}
	
	
	public void testDefaultNotInSubsetOf() {
		// "scopes": {
		//        "subset_of": ["openid", "phone"],
		//        "superset_of": ["openid"],
		//        "default": ["openid", "eduperson"]}
		
		SubsetOfOperation subsetOfOperation = new SubsetOfOperation();
		subsetOfOperation.configure(Arrays.asList("openid", "phone"));
		
		SupersetOfOperation supersetOfOperation = new SupersetOfOperation();
		supersetOfOperation.configure(Collections.singletonList("openid"));
		
		DefaultOperation defaultOperation = new DefaultOperation();
		defaultOperation.configure(Arrays.asList("openid", "eduperson"));
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(subsetOfOperation);
		policyOperations.add(supersetOfOperation);
		policyOperations.add(defaultOperation);
		
		try {
			new DefaultPolicyOperationCombinationValidator().validate(policyOperations);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Not in subset_of [openid, phone]: [openid, eduperson]", e.getMessage());
		}
	}
	
	
	public void testDefaultNotInSupersetOf() {
		// "scopes": {
		//        "subset_of": ["openid", "phone", "eduperson"],
		//        "superset_of": ["openid"],
		//        "default": ["eduperson"]}
		
		SubsetOfOperation subsetOfOperation = new SubsetOfOperation();
		subsetOfOperation.configure(Arrays.asList("openid", "phone", "eduperson"));
		
		SupersetOfOperation supersetOfOperation = new SupersetOfOperation();
		supersetOfOperation.configure(Collections.singletonList("openid"));
		
		DefaultOperation defaultOperation = new DefaultOperation();
		defaultOperation.configure(Collections.singletonList("eduperson"));
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(subsetOfOperation);
		policyOperations.add(supersetOfOperation);
		policyOperations.add(defaultOperation);
		
		try {
			new DefaultPolicyOperationCombinationValidator().validate(policyOperations);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Not in superset_of [openid]: [eduperson]", e.getMessage());
		}
	}
	
	
	public void testDefaultNotInOneOf() {
		
		OneOfOperation oneOfOperation = new OneOfOperation();
		oneOfOperation.configure(Arrays.asList("RS256", "RS384", "RS512"));
		
		DefaultOperation defaultOperation = new DefaultOperation();
		defaultOperation.configure("ES256");
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(oneOfOperation);
		policyOperations.add(defaultOperation);
		
		try {
			new DefaultPolicyOperationCombinationValidator().validate(policyOperations);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Not in one_of [RS256, RS384, RS512]: ES256", e.getMessage());
		}
	}
	
	
	public void testSubsetOfAndSupersetOf() throws PolicyViolationException {
		// "scopes": {
		//        "subset_of": ["openid", "phone", "eduperson"],
		//        "superset_of": ["openid"]}
		
		SubsetOfOperation subsetOfOperation = new SubsetOfOperation();
		subsetOfOperation.configure(Arrays.asList("openid", "phone", "eduperson"));
		
		SupersetOfOperation supersetOfOperation = new SupersetOfOperation();
		supersetOfOperation.configure(Collections.singletonList("openid"));
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(subsetOfOperation);
		policyOperations.add(supersetOfOperation);
		
		assertEquals(policyOperations, new DefaultPolicyOperationCombinationValidator().validate(policyOperations));
	}
	
	
	public void testSubsetOfAndSupersetOf_subsetOfNotInSupersetOf() {
		// "scopes": {
		//        "subset_of": ["phone", "eduperson"],
		//        "superset_of": ["openid"]}
		
		SubsetOfOperation subsetOfOperation = new SubsetOfOperation();
		subsetOfOperation.configure(Arrays.asList("phone", "eduperson"));
		
		SupersetOfOperation supersetOfOperation = new SupersetOfOperation();
		supersetOfOperation.configure(Collections.singletonList("openid"));
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(subsetOfOperation);
		policyOperations.add(supersetOfOperation);
		
		try {
			new DefaultPolicyOperationCombinationValidator().validate(policyOperations);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Not in superset_of [openid]: [phone, eduperson]", e.getMessage());
		}
	}
	
	
	public void testValue() throws PolicyViolationException {
		//        "essential": true,
		//        "value": "RS256"
		
		EssentialOperation essentialOperation = new EssentialOperation();
		essentialOperation.configure(true);
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure("RS256");
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(essentialOperation);
		policyOperations.add(valueOperation);
		
		assertEquals(policyOperations, new DefaultPolicyOperationCombinationValidator().validate(policyOperations));
	}
	
	
	public void testValue_removeRemaining() throws PolicyViolationException {
		//        "value": "RS256",
		//        "one_of": ["RS256", "RS384", "RS512"],
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure("RS256");
		
		OneOfOperation oneOfOperation = new OneOfOperation();
		oneOfOperation.configure(Arrays.asList("RS256", "RS384", "RS512"));
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(valueOperation);
		policyOperations.add(oneOfOperation);
		
		assertEquals(Collections.singletonList(valueOperation), new DefaultPolicyOperationCombinationValidator().validate(policyOperations));
	}
	
	
	public void testValue_removeRemainingTwo() throws PolicyViolationException {
		//        "value": "RS256",
		//        "one_of": ["RS256", "RS384", "RS512"],
		//        "essential": true
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure("RS256");
		
		OneOfOperation oneOfOperation = new OneOfOperation();
		oneOfOperation.configure(Arrays.asList("RS256", "RS384", "RS512"));
		
		EssentialOperation essentialOperation = new EssentialOperation();
		essentialOperation.configure(true);
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(valueOperation);
		policyOperations.add(oneOfOperation);
		policyOperations.add(essentialOperation);
		
		assertEquals(Collections.singletonList(valueOperation), new DefaultPolicyOperationCombinationValidator().validate(policyOperations));
	}
	
	
	public void testValue_removeRemaining_essentialCombinesWithAll() throws PolicyViolationException {
		//        "essential": true,
		//        "value": "RS256",
		//        "one_of": ["RS256", "RS384", "RS512"],
		
		EssentialOperation essentialOperation = new EssentialOperation();
		essentialOperation.configure(true);
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure("RS256");
		
		OneOfOperation oneOfOperation = new OneOfOperation();
		oneOfOperation.configure(Arrays.asList("RS256", "RS384", "RS512"));
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(essentialOperation);
		policyOperations.add(valueOperation);
		policyOperations.add(oneOfOperation);
		
		assertEquals(Arrays.asList(essentialOperation, valueOperation), new DefaultPolicyOperationCombinationValidator().validate(policyOperations));
	}
	
	
	public void testValueWithSuperiorSubsetOf() throws PolicyViolationException {
		
		SubsetOfOperation subsetOfOperation = new SubsetOfOperation();
		subsetOfOperation.configure(Arrays.asList("openid", "email", "profile"));
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure(Arrays.asList("openid", "email"));
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(subsetOfOperation);
		policyOperations.add(valueOperation);
		
		assertEquals(policyOperations, new DefaultPolicyOperationCombinationValidator().validate(policyOperations));
	}
	
	
	public void testValueWithSuperiorSupersetOf() throws PolicyViolationException {
		
		SupersetOfOperation supersetOfOperation = new SupersetOfOperation();
		supersetOfOperation.configure(Collections.singletonList("openid"));
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure(Arrays.asList("openid", "email"));
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(supersetOfOperation);
		policyOperations.add(valueOperation);
		
		assertEquals(policyOperations, new DefaultPolicyOperationCombinationValidator().validate(policyOperations));
	}
	
	
	public void testValueWithSuperiorSubsetOf_violation() {
		
		SubsetOfOperation subsetOfOperation = new SubsetOfOperation();
		subsetOfOperation.configure(Arrays.asList("openid", "email", "profile"));
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure(Collections.singletonList("address"));
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(subsetOfOperation);
		policyOperations.add(valueOperation);
		
		try {
			new DefaultPolicyOperationCombinationValidator().validate(policyOperations);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Not in subset_of [openid, email, profile]: [address]", e.getMessage());
		}
	}
	
	
	public void testValueWithSuperiorSupersetOf_violation() {
		
		SupersetOfOperation supersetOfOperation = new SupersetOfOperation();
		supersetOfOperation.configure(Collections.singletonList("openid"));
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure(Collections.singletonList("email"));
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(supersetOfOperation);
		policyOperations.add(valueOperation);
		
		try {
			new DefaultPolicyOperationCombinationValidator().validate(policyOperations);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Not in superset_of [openid]: [email]", e.getMessage());
		}
	}
	
	
	
	
	
	public void testValueWithOneOf() throws PolicyViolationException {
		//        "one_of": ["RS256", "RS384", "RS512"]
		//        "value": "RS256"
		
		OneOfOperation oneOfOperation = new OneOfOperation();
		oneOfOperation.configure(Arrays.asList("RS256", "RS384", "RS512"));
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure("RS256");
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(oneOfOperation);
		policyOperations.add(valueOperation);
		
		assertEquals(policyOperations, new DefaultPolicyOperationCombinationValidator().validate(policyOperations));
	}
	
	
	public void testValueWithOneOf_violation() {
		//        "one_of": ["RS256", "RS384", "RS512"]
		//        "value": "RS256"
		
		OneOfOperation oneOfOperation = new OneOfOperation();
		oneOfOperation.configure(Arrays.asList("RS256", "RS384", "RS512"));
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure("ES256");
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		policyOperations.add(oneOfOperation);
		policyOperations.add(valueOperation);
		
		try {
			new DefaultPolicyOperationCombinationValidator().validate(policyOperations);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Not in one_of [RS256, RS384, RS512]: ES256", e.getMessage());
		}
	}
}
