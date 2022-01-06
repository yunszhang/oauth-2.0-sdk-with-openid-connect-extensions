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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.assurance.Policy;
import com.nimbusds.openid.connect.sdk.assurance.Procedure;
import com.nimbusds.openid.connect.sdk.assurance.Status;


public class ValidationMethodTest extends TestCase {


	public void testMinimal() throws ParseException {
		
		ValidationMethodType type = ValidationMethodType.VDIG;
		ValidationMethod method = new ValidationMethod(type, null, null, null);
		assertEquals(type, method.getType());
		assertNull(method.getPolicy());
		assertNull(method.getProcedure());
		assertNull(method.getStatus());
		
		JSONObject jsonObject = method.toJSONObject();
		assertEquals(type.getValue(), jsonObject.get("type"));
		assertEquals(1, jsonObject.size());
		
		ValidationMethod parsed = ValidationMethod.parse(jsonObject);
		assertEquals(type, parsed.getType());
		assertNull(parsed.getPolicy());
		assertNull(parsed.getProcedure());
		assertNull(parsed.getStatus());
		
		assertEquals(method, parsed);
		assertEquals(method.hashCode(), parsed.hashCode());
	}

	public void testAllSet() throws ParseException {
		
		ValidationMethodType type = ValidationMethodType.VDIG;
		Policy policy = new Policy("some-policy");
		Procedure procedure = new Procedure("some-procedure");
		Status status = new Status("some-status");
		
		ValidationMethod method = new ValidationMethod(type, policy, procedure, status);
		assertEquals(type, method.getType());
		assertEquals(policy, method.getPolicy());
		assertEquals(procedure, method.getProcedure());
		assertEquals(status, method.getStatus());
		
		JSONObject jsonObject = method.toJSONObject();
		assertEquals(type.getValue(), jsonObject.get("type"));
		assertEquals(policy.getValue(), jsonObject.get("policy"));
		assertEquals(procedure.getValue(), jsonObject.get("procedure"));
		assertEquals(status.getValue(), jsonObject.get("status"));
		assertEquals(4, jsonObject.size());
		
		ValidationMethod parsed = ValidationMethod.parse(jsonObject);
		assertEquals(type, parsed.getType());
		assertEquals(policy, parsed.getPolicy());
		assertEquals(procedure, parsed.getProcedure());
		assertEquals(status, parsed.getStatus());
		
		assertEquals(method, parsed);
		assertEquals(method.hashCode(), parsed.hashCode());
	}
	
	
	public void testParse_emptyJSONObject() {
		
		try {
			ValidationMethod.parse(new JSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key type", e.getMessage());
		}
	}
}
