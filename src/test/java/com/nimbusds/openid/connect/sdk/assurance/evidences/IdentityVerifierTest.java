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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.secevent.sdk.claims.TXN;


public class IdentityVerifierTest extends TestCase {
	
	
	public void testNullParams() throws ParseException {
		
		IdentityVerifier verifier = new IdentityVerifier((Organization) null, null);
		assertNull(verifier.getOrganizationEntity());
		assertNull(verifier.getOrganizationString());
		assertNull(verifier.getOrganization());
		assertNull(verifier.getTXN());
		
		JSONObject jsonObject = verifier.toJSONObject();
		assertTrue(jsonObject.isEmpty());
		
		verifier = IdentityVerifier.parse(jsonObject);
		assertNull(verifier.getOrganizationEntity());
		assertNull(verifier.getOrganizationString());
		assertNull(verifier.getOrganization());
		assertNull(verifier.getTXN());
		
		assertEquals("Equality", verifier, IdentityVerifier.parse(jsonObject));
		assertEquals("Hash code", verifier.hashCode(), IdentityVerifier.parse(jsonObject).hashCode());
	}
	
	
	public void testNullParams_deprecatedConstructor() throws ParseException {
		
		IdentityVerifier verifier = new IdentityVerifier((String)null, null);
		assertNull(verifier.getOrganizationEntity());
		assertNull(verifier.getOrganizationString());
		assertNull(verifier.getOrganization());
		assertNull(verifier.getTXN());
		
		JSONObject jsonObject = verifier.toJSONObject();
		assertTrue(jsonObject.isEmpty());
		
		verifier = IdentityVerifier.parse(jsonObject);
		assertNull(verifier.getOrganizationEntity());
		assertNull(verifier.getOrganizationString());
		assertNull(verifier.getOrganization());
		assertNull(verifier.getTXN());
		
		assertEquals("Equality", verifier, IdentityVerifier.parse(jsonObject));
		assertEquals("Hash code", verifier.hashCode(), IdentityVerifier.parse(jsonObject).hashCode());
	}
	
	
	public void testAllSetParams() throws ParseException {
		
		Organization org = new Organization("example.com");
		TXN txn = new TXN("c9155d5d-8b8d-4d85-8a0c-caae01032c1f");
		IdentityVerifier verifier = new IdentityVerifier(org, txn);
		assertEquals(org, verifier.getOrganizationEntity());
		assertEquals(org.getValue(), verifier.getOrganizationString());
		assertEquals(org.getValue(), verifier.getOrganization());
		assertEquals(txn, verifier.getTXN());
		
		JSONObject jsonObject = verifier.toJSONObject();
		assertEquals(org.getValue(), jsonObject.get("organization"));
		assertEquals(txn.getValue(), jsonObject.get("txn"));
		assertEquals(2, jsonObject.size());
		
		verifier = IdentityVerifier.parse(jsonObject);
		
		assertEquals(org, verifier.getOrganizationEntity());
		assertEquals(org.getValue(), verifier.getOrganizationString());
		assertEquals(org.getValue(), verifier.getOrganization());
		assertEquals(txn, verifier.getTXN());
		
		assertEquals("Equality", verifier, IdentityVerifier.parse(jsonObject));
		assertEquals("Hash code", verifier.hashCode(), IdentityVerifier.parse(jsonObject).hashCode());
	}
	
	
	public void testAllSetParams_deprecatedConstructor() throws ParseException {
		
		String orgString = "example.com";
		TXN txn = new TXN("c9155d5d-8b8d-4d85-8a0c-caae01032c1f");
		IdentityVerifier verifier = new IdentityVerifier(orgString, txn);
		assertEquals(new Organization(orgString), verifier.getOrganizationEntity());
		assertEquals(orgString, verifier.getOrganizationString());
		assertEquals(orgString, verifier.getOrganization());
		assertEquals(txn, verifier.getTXN());
		
		JSONObject jsonObject = verifier.toJSONObject();
		assertEquals(orgString, jsonObject.get("organization"));
		assertEquals(txn.getValue(), jsonObject.get("txn"));
		assertEquals(2, jsonObject.size());
		
		verifier = IdentityVerifier.parse(jsonObject);
		
		assertEquals(new Organization(orgString), verifier.getOrganizationEntity());
		assertEquals(orgString, verifier.getOrganizationString());
		assertEquals(orgString, verifier.getOrganization());
		assertEquals(txn, verifier.getTXN());
		
		assertEquals("Equality", verifier, IdentityVerifier.parse(jsonObject));
		assertEquals("Hash code", verifier.hashCode(), IdentityVerifier.parse(jsonObject).hashCode());
	}
	
	
	public void testInequality() {
		
		IdentityVerifier a = new IdentityVerifier(new Organization("a"), null);
		IdentityVerifier b = new IdentityVerifier(new Organization("b"), null);
		
		assertNotSame(a, b);
		assertNotSame(a.hashCode(), b.hashCode());
	}
	
	
	public void testParseExample() throws ParseException {
		
		String json =
			"{" +
			"  \"organization\": \"Deutsche Post\"," +
			"  \"txn\": \"1aa05779-0775-470f-a5c4-9f1f5e56cf06\"" +
			"}";
		
		IdentityVerifier verifier = IdentityVerifier.parse(JSONObjectUtils.parse(json));
		assertEquals(new Organization("Deutsche Post"), verifier.getOrganizationEntity());
		assertEquals(new TXN("1aa05779-0775-470f-a5c4-9f1f5e56cf06"), verifier.getTXN());
	}
}
