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

package com.nimbusds.openid.connect.sdk.federation.policy.language;


import java.util.Arrays;
import java.util.Collections;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.DefaultOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.SubsetOfOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.SupersetOfOperation;


public class PolicyEntryTest extends TestCase {
	

	public void testScopesExample() throws ParseException {
		
		String json =
			"{\"subset_of\": [\"openid\", \"eduperson\", \"phone\"]," +
			"\"superset_of\": [\"openid\"]," +
			"\"default\": [\"openid\", \"eduperson\"]}";
		
		JSONObject spec = JSONObjectUtils.parse(json);
		
		PolicyEntry policyEntry = PolicyEntry.parse("scope", spec);
		
		assertEquals("scope", policyEntry.getParameterName());
		
		System.out.println(policyEntry.getOperations());
		
		for (PolicyOperation op: policyEntry.getOperations()) {
			
			if (SubsetOfOperation.NAME.equals(op.getOperationName())) {
			
				SubsetOfOperation subsetOfOperation = (SubsetOfOperation)op;
				assertEquals(Arrays.asList("openid", "eduperson", "phone"), subsetOfOperation.getStringListConfiguration());
			
			} else if (SupersetOfOperation.NAME.equals(op.getOperationName())) {
			
				SupersetOfOperation supersetOfOperation = (SupersetOfOperation)op;
				assertEquals(Collections.singletonList("openid"), supersetOfOperation.getStringListConfiguration());
			
			} else	if (DefaultOperation.NAME.equals(op.getOperationName())) {
			
				DefaultOperation defaultOperation = (DefaultOperation)op;
				assertEquals(Arrays.asList("openid", "eduperson"), defaultOperation.getStringListConfiguration());
			
			} else {
				fail();
			}
			
		}
		assertEquals(3, policyEntry.getOperations().size());
	}
}
