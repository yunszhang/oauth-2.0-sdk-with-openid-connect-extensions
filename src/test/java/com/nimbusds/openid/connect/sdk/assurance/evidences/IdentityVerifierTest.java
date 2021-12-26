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
		
		IdentityVerifier identityVerifier = new IdentityVerifier(null, null);
		assertNull(identityVerifier.getOrganization());
		assertNull(identityVerifier.getTXN());
		
		JSONObject jsonObject = identityVerifier.toJSONObject();
		assertTrue(jsonObject.isEmpty());
		
		identityVerifier = IdentityVerifier.parse(jsonObject);
		assertNull(identityVerifier.getOrganization());
		assertNull(identityVerifier.getTXN());
		
		assertEquals("Equality", identityVerifier, IdentityVerifier.parse(jsonObject));
		assertEquals("Hash code", identityVerifier.hashCode(), IdentityVerifier.parse(jsonObject).hashCode());
	}
	
	
	public void testAllSetParams() throws ParseException {
		
		String org = "example.com";
		TXN txn = new TXN("c9155d5d-8b8d-4d85-8a0c-caae01032c1f");
		IdentityVerifier identityVerifier = new IdentityVerifier(org, txn);
		assertEquals(org, identityVerifier.getOrganization());
		assertEquals(txn, identityVerifier.getTXN());
		
		JSONObject jsonObject = identityVerifier.toJSONObject();
		assertEquals(org, jsonObject.get("organization"));
		assertEquals(txn.getValue(), jsonObject.get("txn"));
		assertEquals(2, jsonObject.size());
		
		identityVerifier = IdentityVerifier.parse(jsonObject);
		
		assertEquals(org, identityVerifier.getOrganization());
		assertEquals(txn, identityVerifier.getTXN());
		
		assertEquals("Equality", identityVerifier, IdentityVerifier.parse(jsonObject));
		assertEquals("Hash code", identityVerifier.hashCode(), IdentityVerifier.parse(jsonObject).hashCode());
	}
	
	
	public void testParseExample() throws ParseException {
		
		String json =
			"{" +
			"  \"organization\": \"Deutsche Post\"," +
			"  \"txn\": \"1aa05779-0775-470f-a5c4-9f1f5e56cf06\"" +
			"}";
		
		IdentityVerifier verifier = IdentityVerifier.parse(JSONObjectUtils.parse(json));
		assertEquals("Deutsche Post", verifier.getOrganization());
		assertEquals(new TXN("1aa05779-0775-470f-a5c4-9f1f5e56cf06"), verifier.getTXN());
	}
}
