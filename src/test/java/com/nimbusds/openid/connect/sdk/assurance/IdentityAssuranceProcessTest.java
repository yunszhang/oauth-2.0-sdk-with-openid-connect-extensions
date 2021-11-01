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

package com.nimbusds.openid.connect.sdk.assurance;


import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;


public class IdentityAssuranceProcessTest extends TestCase {
	
	
	public void testConstructor_allSet() throws ParseException {
		
		Policy policy = new Policy("some-policy");
		Procedure procedure = new Procedure("some-procedure");
		Status status = new Status("some-status");
		
		IdentityAssuranceProcess process = new IdentityAssuranceProcess(
			policy,
			procedure,
			status
		);
		
		assertEquals(policy, process.getPolicy());
		assertEquals(procedure, process.getProcedure());
		assertEquals(status, process.getStatus());
		
		assertEquals(
			process,
			new IdentityAssuranceProcess(
				policy,
				procedure,
				status
			)
		);
		
		assertEquals(
			process.hashCode(),
			new IdentityAssuranceProcess(
				policy,
				procedure,
				status
			).hashCode()
		);
		
		JSONObject jsonObject = process.toJSONObject();
		assertEquals(policy.getValue(), jsonObject.get("policy"));
		assertEquals(procedure.getValue(), jsonObject.get("procedure"));
		assertEquals(status.getValue(), jsonObject.get("status"));
		assertEquals(3, jsonObject.size());
		
		process = IdentityAssuranceProcess.parse(jsonObject);
		assertEquals(policy, process.getPolicy());
		assertEquals(procedure, process.getProcedure());
		assertEquals(status, process.getStatus());
	}
	
	
	public void testConstructor_policyOnly() throws ParseException {
		
		Policy policy = new Policy("some-policy");
		
		IdentityAssuranceProcess process = new IdentityAssuranceProcess(
			policy,
			null,
			null
		);
		
		assertEquals(policy, process.getPolicy());
		assertNull(process.getProcedure());
		assertNull(process.getStatus());
		
		assertEquals(
			process,
			new IdentityAssuranceProcess(
				policy,
				null,
				null
			)
		);
		
		assertEquals(
			process.hashCode(),
			new IdentityAssuranceProcess(
				policy,
				null,
				null
			).hashCode()
		);
		
		JSONObject jsonObject = process.toJSONObject();
		assertEquals(policy.getValue(), jsonObject.get("policy"));
		assertEquals(1, jsonObject.size());
		
		process = IdentityAssuranceProcess.parse(jsonObject);
		assertEquals(policy, process.getPolicy());
		assertNull(process.getProcedure());
		assertNull(process.getStatus());
	}
	
	
	public void testConstructor_procedureOnly() throws ParseException {
		
		Policy policy = null;
		Procedure procedure = new Procedure("some-procedure");
		Status status = null;
		
		IdentityAssuranceProcess process = new IdentityAssuranceProcess(
			null,
			procedure,
			null
		);
		
		assertNull(process.getPolicy());
		assertEquals(procedure, process.getProcedure());
		assertNull(process.getStatus());
		
		assertEquals(
			process,
			new IdentityAssuranceProcess(
				null,
				procedure,
				null
			)
		);
		
		assertEquals(
			process.hashCode(),
			new IdentityAssuranceProcess(
				null,
				procedure,
				null
			).hashCode()
		);
		
		JSONObject jsonObject = process.toJSONObject();
		assertEquals(procedure.getValue(), jsonObject.get("procedure"));
		assertEquals(1, jsonObject.size());
		
		process = IdentityAssuranceProcess.parse(jsonObject);
		assertNull(process.getPolicy());
		assertEquals(procedure, process.getProcedure());
		assertNull(process.getStatus());
	}
	
	
	public void testConstructor_statusOnly() throws ParseException {
		
		Status status = new Status("some-status");
		
		IdentityAssuranceProcess process = new IdentityAssuranceProcess(
			null,
			null,
			status
		);
		
		assertNull(process.getPolicy());
		assertNull(process.getProcedure());
		assertEquals(status, process.getStatus());
		
		assertEquals(
			process,
			new IdentityAssuranceProcess(
				null,
				null,
				status
			)
		);
		
		assertEquals(
			process.hashCode(),
			new IdentityAssuranceProcess(
				null,
				null,
				status
			).hashCode()
		);
		
		JSONObject jsonObject = process.toJSONObject();
		assertEquals(status.getValue(), jsonObject.get("status"));
		assertEquals(1, jsonObject.size());
		
		process = IdentityAssuranceProcess.parse(jsonObject);
		assertNull(process.getPolicy());
		assertNull(process.getProcedure());
		assertEquals(status, process.getStatus());
	}
	
	
	public void testRejectNoneSet() {
		
		try {
			new IdentityAssuranceProcess(null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("At least one assurance process element must be specified", e.getMessage());
		}
		
		try {
			IdentityAssuranceProcess.parse(new JSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("At least one assurance process element must be specified", e.getMessage());
		}
	}
	
	
	public void testParseEmptyElements() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("policy", "");
		jsonObject.put("procedure", "");
		jsonObject.put("status", "some-status");
		
		IdentityAssuranceProcess process = IdentityAssuranceProcess.parse(jsonObject);
		assertNull(process.getPolicy());
		assertNull(process.getProcedure());
		assertEquals(new Status("some-status"), process.getStatus());
	}
}
