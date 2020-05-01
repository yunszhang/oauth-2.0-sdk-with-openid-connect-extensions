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

package com.nimbusds.openid.connect.sdk.federation.policy;


import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.federation.policy.language.OperationName;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.DefaultOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.SubsetOfOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.SupersetOfOperation;


public class MetadataPolicyEntryTest extends TestCase {
	
	
	public void testConstructor() throws PolicyViolationException {
		
		String paramName = "scope";
		SubsetOfOperation op1 = new SubsetOfOperation();
		op1.configure(Arrays.asList("openid", "eduperson", "phone"));
		List<PolicyOperation> ops = Collections.singletonList((PolicyOperation)op1);
		
		MetadataPolicyEntry entry = new MetadataPolicyEntry("scope", ops);
		
		assertEquals(paramName, entry.getKey());
		assertEquals(paramName, entry.getParameterName());
		
		assertEquals(ops, entry.getValue());
		assertEquals(ops, entry.getPolicyOperations());
		
		Map<OperationName,PolicyOperation> map = entry.getOperationsMap();
		assertEquals(op1, map.get(op1.getOperationName()));
		assertEquals(1, map.size());
		
		List<String> input = Arrays.asList("openid", "email");
		List<String> output = (List<String>)entry.apply(input);
		assertEquals(Collections.singletonList("openid"), output);
	}
	
	
	public void testEmpty() {
		
		MetadataPolicyEntry entry = new MetadataPolicyEntry("scope", null);
		
		assertEquals("scope", entry.getKey());
		assertEquals("scope", entry.getParameterName());
		
		assertNull(entry.getValue());
		assertNull(entry.getPolicyOperations());
		
		assertTrue(entry.getOperationsMap().isEmpty());
	}
	
	
	public void testScopesExample() throws ParseException, PolicyViolationException {
		
		String json =
			"{\"subset_of\": [\"openid\", \"eduperson\", \"phone\"]," +
			 "\"superset_of\": [\"openid\"]," +
			 "\"default\": [\"openid\", \"eduperson\"]}";
		
		JSONObject spec = JSONObjectUtils.parse(json);
		
		MetadataPolicyEntry policyEntry = MetadataPolicyEntry.parse("scope", spec);
		
		assertEquals("scope", policyEntry.getKey());
		
		for (PolicyOperation op: policyEntry.getPolicyOperations()) {
			
			if (op instanceof SubsetOfOperation) {
				SubsetOfOperation subsetOfOperation = (SubsetOfOperation) op;
				assertEquals(Arrays.asList("openid", "eduperson", "phone"), subsetOfOperation.getStringListConfiguration());
			} else if (op instanceof SupersetOfOperation) {
				SupersetOfOperation supersetOfOperation = (SupersetOfOperation) op;
				assertEquals(Collections.singletonList("openid"), supersetOfOperation.getStringListConfiguration());
			} else if (op instanceof DefaultOperation) {
				DefaultOperation defaultOperation = (DefaultOperation) op;
				assertEquals(Arrays.asList("openid", "eduperson"), defaultOperation.getStringListConfiguration());
			} else {
				fail();
			}
		}
		
		assertEquals(3, policyEntry.getValue().size());
	}
}
