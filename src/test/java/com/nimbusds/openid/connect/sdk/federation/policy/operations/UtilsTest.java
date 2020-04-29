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

import junit.framework.TestCase;

import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;


public class UtilsTest extends TestCase {
	
	
	public void testGetPolicyOperationByType_null() {
		
		assertNull(Utils.getPolicyOperationByType(null, SubsetOfOperation.class));
	}
	
	
	public void testGetPolicyOperationByType_one() {
		
		SubsetOfOperation op = new SubsetOfOperation();
		op.configure(Arrays.asList("openid", "email"));
		
		assertEquals(op, Utils.getPolicyOperationByType(Collections.singletonList((PolicyOperation) op), SubsetOfOperation.class));
	}
	
	
	public void testGetPolicyOperationByType_noneFound() {
		
		SubsetOfOperation op = new SubsetOfOperation();
		op.configure(Arrays.asList("openid", "email"));
		
		assertNull(Utils.getPolicyOperationByType(Collections.singletonList((PolicyOperation) op), DefaultOperation.class));
	}
}
