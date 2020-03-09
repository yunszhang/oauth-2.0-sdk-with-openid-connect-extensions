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
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;
import com.nimbusds.openid.connect.sdk.claims.Address;


public class UtilityBillEvidenceTest extends TestCase {
	
	
	public void testMinimal() throws ParseException {
		
		UtilityBillEvidence utilityBillEvidence = new UtilityBillEvidence(null, null, null);
		
		assertNull(utilityBillEvidence.getUtilityProviderName());
		assertNull(utilityBillEvidence.getUtilityProviderAddress());
		assertNull(utilityBillEvidence.getUtilityBillDate());
		
		JSONObject jsonObject = utilityBillEvidence.toJSONObject();
		assertEquals(IdentityEvidenceType.UTILITY_BILL.getValue(), jsonObject.get("type"));
		assertEquals(1, jsonObject.size());
		
		utilityBillEvidence = UtilityBillEvidence.parse(jsonObject);
		
		assertNull(utilityBillEvidence.getUtilityProviderName());
		assertNull(utilityBillEvidence.getUtilityProviderAddress());
		assertNull(utilityBillEvidence.getUtilityBillDate());
	}
	
	
	public void testMethods() throws ParseException {
		
		String name = "My Provider";
		Address address = new Address();
		address.setLocality("Sofia");
		SimpleDate ts = new SimpleDate(2019, 12, 1);
		
		UtilityBillEvidence evidence = new UtilityBillEvidence(name, address, ts);
		
		assertEquals(IdentityEvidenceType.UTILITY_BILL, evidence.getEvidenceType());
		assertEquals(name, evidence.getUtilityProviderName());
		assertEquals(address, evidence.getUtilityProviderAddress());
		assertEquals(ts, evidence.getUtilityBillDate());
		
		JSONObject jsonObject = evidence.toJSONObject();
		assertEquals("utility_bill", jsonObject.get("type"));
		JSONObject providerObject = JSONObjectUtils.getJSONObject(jsonObject, "provider");
		assertEquals(name, providerObject.get("name"));
		assertEquals(address.getLocality(), providerObject.get("locality"));
		assertEquals(2, providerObject.size());
		assertEquals(ts.toISO8601String(), jsonObject.get("date"));
		assertEquals(3, jsonObject.size());
		
		evidence = UtilityBillEvidence.parse(jsonObject);
		
		assertEquals(IdentityEvidenceType.UTILITY_BILL, evidence.getEvidenceType());
		assertEquals(name, evidence.getUtilityProviderName());
		assertEquals(address.toJSONObject(), evidence.getUtilityProviderAddress().toJSONObject());
		assertEquals(ts, evidence.getUtilityBillDate());
	}
}
