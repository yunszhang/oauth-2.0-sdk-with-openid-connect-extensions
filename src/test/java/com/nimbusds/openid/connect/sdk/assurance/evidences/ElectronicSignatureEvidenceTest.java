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
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.date.DateWithTimeZoneOffset;


public class ElectronicSignatureEvidenceTest extends TestCase {
	
	
	private static final SignatureType QES = new SignatureType("QES");
	
	
	public void testMinimal() throws ParseException {
		
		ElectronicSignatureEvidence evidence = new ElectronicSignatureEvidence(QES, null, null, null);
		
		assertEquals(QES, evidence.getSignatureType());
		assertNull(evidence.getIssuer());
		assertNull(evidence.getSerialNumberString());
		assertNull(evidence.getCreationTime());
		
		JSONObject jsonObject = evidence.toJSONObject();
		assertEquals(IdentityEvidenceType.ELECTRONIC_SIGNATURE.getValue(), jsonObject.get("type"));
		assertEquals(QES.getValue(), jsonObject.get("signature_type"));
		assertEquals(2, jsonObject.size());
		
		evidence = ElectronicSignatureEvidence.parse(jsonObject);
		
		assertEquals(QES, evidence.getSignatureType());
		assertNull(evidence.getIssuer());
		assertNull(evidence.getSerialNumberString());
		assertNull(evidence.getCreationTime());
	}
	
	
	public void testMethods() throws ParseException {
		
		Issuer issuer = new Issuer("QES issuer");
		String number = "6efe7fa4-91d8-4821-9859-eaab40f321b6";
		DateWithTimeZoneOffset ts = DateWithTimeZoneOffset.parseISO8601String("2012-04-23T18:25Z");
		
		ElectronicSignatureEvidence evidence = new ElectronicSignatureEvidence(QES, issuer, number, ts);
		
		assertEquals(IdentityEvidenceType.ELECTRONIC_SIGNATURE, evidence.getEvidenceType());
		assertEquals(QES, evidence.getSignatureType());
		assertEquals(issuer, evidence.getIssuer());
		assertEquals(number, evidence.getSerialNumberString());
		assertEquals(ts, evidence.getCreationTime());
		
		JSONObject jsonObject = evidence.toJSONObject();
		assertEquals(IdentityEvidenceType.ELECTRONIC_SIGNATURE.getValue(), jsonObject.get("type"));
		assertEquals(QES.getValue(), jsonObject.get("signature_type"));
		assertEquals(issuer.getValue(), jsonObject.get("issuer"));
		assertEquals(number, jsonObject.get("serial_number"));
		assertEquals(ts.toISO8601String(), jsonObject.get("created_at"));
		assertEquals(5, jsonObject.size());
		
		evidence = ElectronicSignatureEvidence.parse(jsonObject);
		
		assertEquals(IdentityEvidenceType.ELECTRONIC_SIGNATURE, evidence.getEvidenceType());
		assertEquals(QES, evidence.getSignatureType());
		assertEquals(issuer, evidence.getIssuer());
		assertEquals(number, evidence.getSerialNumberString());
		assertEquals(ts, evidence.getCreationTime());
	}
}
