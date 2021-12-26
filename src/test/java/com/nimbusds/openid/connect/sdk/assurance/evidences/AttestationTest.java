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
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;


public class AttestationTest extends TestCase {


	public void testMinimal()
		throws ParseException {
		
		Attestation attestation = new Attestation(VouchType.WRITTEN_ATTESTATION, null, null, null, null, null);
		
		assertEquals(VouchType.WRITTEN_ATTESTATION, attestation.getType());
		assertNull(attestation.getReferenceNumber());
		assertNull(attestation.getPersonalNumber());
		assertNull(attestation.getDateOfIssuance());
		assertNull(attestation.getDateOfExpiry());
		assertNull(attestation.getVoucher());
		
		JSONObject jsonObject = attestation.toJSONObject();
		assertEquals(VouchType.WRITTEN_ATTESTATION.getValue(), jsonObject.get("type"));
		assertEquals(1, jsonObject.size());
		
		attestation = Attestation.parse(jsonObject);
		
		assertEquals(VouchType.WRITTEN_ATTESTATION, attestation.getType());
		assertNull(attestation.getReferenceNumber());
		assertNull(attestation.getPersonalNumber());
		assertNull(attestation.getDateOfIssuance());
		assertNull(attestation.getDateOfExpiry());
		assertNull(attestation.getVoucher());
		
		assertEquals("Equality", attestation, Attestation.parse(jsonObject));
		assertEquals("Hash code", attestation.hashCode(), Attestation.parse(jsonObject).hashCode());
	}


	public void testFullySet()
		throws ParseException {
		
		VouchType type = VouchType.WRITTEN_ATTESTATION;
		ReferenceNumber referenceNumber = new ReferenceNumber("438f08d4-15e1-472c-8d41-ac4c46228ed0");
		PersonalNumber personalNumber = new PersonalNumber("34895891");
		SimpleDate dateOfIssuance = new SimpleDate(2021, 12, 31);
		SimpleDate dateOfExpiry = new SimpleDate(2022, 1, 31);
		Voucher voucher = new Voucher(new Name("Some entity"), null, null, null, new Organization("Some org"));
		
		Attestation attestation = new Attestation(
			type,
			referenceNumber,
			personalNumber,
			dateOfIssuance,
			dateOfExpiry,
			voucher
		);
		
		assertEquals(type, attestation.getType());
		assertEquals(referenceNumber, attestation.getReferenceNumber());
		assertEquals(personalNumber, attestation.getPersonalNumber());
		assertEquals(dateOfIssuance, attestation.getDateOfIssuance());
		assertEquals(dateOfExpiry, attestation.getDateOfExpiry());
		assertEquals(voucher, attestation.getVoucher());
		
		JSONObject jsonObject = attestation.toJSONObject();
		assertEquals(type.getValue(), jsonObject.get("type"));
		assertEquals(referenceNumber.getValue(), jsonObject.get("reference_number"));
		assertEquals(personalNumber.getValue(), jsonObject.get("personal_number"));
		assertEquals(dateOfIssuance.toISO8601String(), jsonObject.get("date_of_issuance"));
		assertEquals(dateOfExpiry.toISO8601String(), jsonObject.get("date_of_expiry"));
		assertEquals(voucher.toJSONObject(), JSONObjectUtils.getJSONObject(jsonObject, "voucher"));
		assertEquals(6, jsonObject.size());
		
		attestation = Attestation.parse(jsonObject);
		
		assertEquals(type, attestation.getType());
		assertEquals(referenceNumber, attestation.getReferenceNumber());
		assertEquals(personalNumber, attestation.getPersonalNumber());
		assertEquals(dateOfIssuance, attestation.getDateOfIssuance());
		assertEquals(dateOfExpiry, attestation.getDateOfExpiry());
		assertEquals(voucher, attestation.getVoucher());
		
		assertEquals("Equality", attestation, Attestation.parse(jsonObject));
		assertEquals("Hash code", attestation.hashCode(), Attestation.parse(jsonObject).hashCode());
	}
	
	
	public void testRequireType() {
		
		try {
			new Attestation(null, null, null, null, null, null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testParseEmpty() {
		
		try {
			Attestation.parse(new JSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key type", e.getMessage());
		}
	}
	
	
	public void testParseExample()
		throws ParseException {
		
		String json = "{" +
			"\"type\": \"digital_attestation\"," +
			"\"reference_number\": \"6485-1619-3976-6671\"," +
			"\"date_of_issuance\": \"2021-06-04\"," +
			"\"voucher\": {" +
			"    \"organization\": \"HMP Dartmoor\"" +
			"    }" +
			"}";
		
		Attestation attestation = Attestation.parse(JSONObjectUtils.parse(json));
		
		assertEquals(VouchType.DIGITAL_ATTESTATION, attestation.getType());
		assertEquals(new ReferenceNumber("6485-1619-3976-6671"), attestation.getReferenceNumber());
		assertEquals(new SimpleDate(2021, 6, 4), attestation.getDateOfIssuance());
		assertEquals(new Organization("HMP Dartmoor"), attestation.getVoucher().getOrganization());
	}
}
