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


import java.util.Date;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.date.DateWithTimeZoneOffset;


public class QESEvidenceTest extends TestCase {
	
	
	public void testMinimal() throws ParseException {
		
		QESEvidence evidence = new QESEvidence(null, null, null);
		
		assertNull(evidence.getQESIssuer());
		assertNull(evidence.getQESSerialNumberString());
		assertNull(evidence.getQESCreationTime());
		
		JSONObject jsonObject = evidence.toJSONObject();
		assertEquals(IdentityEvidenceType.QES.getValue(), jsonObject.get("type"));
		assertEquals(1, jsonObject.size());
		
		evidence = QESEvidence.parse(jsonObject);
		
		assertNull(evidence.getQESIssuer());
		assertNull(evidence.getQESSerialNumberString());
		assertNull(evidence.getQESCreationTime());
		
		assertEquals("Equality", evidence, QESEvidence.parse(jsonObject));
		assertEquals("Hash code", evidence.hashCode(), QESEvidence.parse(jsonObject).hashCode());
	}
	
	
	public void testMethods() throws ParseException {
		
		Issuer issuer = new Issuer("QES issuer");
		String number = "6efe7fa4-91d8-4821-9859-eaab40f321b6";
		DateWithTimeZoneOffset ts = new DateWithTimeZoneOffset(new Date(), 120);
		
		QESEvidence evidence = new QESEvidence(issuer, number, ts);
		
		assertEquals(IdentityEvidenceType.QES, evidence.getEvidenceType());
		assertEquals(issuer, evidence.getQESIssuer());
		assertEquals(number, evidence.getQESSerialNumberString());
		assertEquals(ts, evidence.getQESCreationTime());
		
		JSONObject jsonObject = evidence.toJSONObject();
		assertEquals(IdentityEvidenceType.QES.getValue(), jsonObject.get("type"));
		assertEquals(issuer.getValue(), jsonObject.get("issuer"));
		assertEquals(number, jsonObject.get("serial_number"));
		assertEquals(ts.toISO8601String(), jsonObject.get("created_at"));
		assertEquals(4, jsonObject.size());
		
		evidence = QESEvidence.parse(jsonObject);
		
		assertEquals(IdentityEvidenceType.QES, evidence.getEvidenceType());
		assertEquals(issuer, evidence.getQESIssuer());
		assertEquals(number, evidence.getQESSerialNumberString());
		assertEquals(ts.toISO8601String(), evidence.getQESCreationTime().toISO8601String());
		
		assertEquals("Equality", evidence, QESEvidence.parse(jsonObject));
		assertEquals("Hash code", evidence.hashCode(), QESEvidence.parse(jsonObject).hashCode());
	}
}
