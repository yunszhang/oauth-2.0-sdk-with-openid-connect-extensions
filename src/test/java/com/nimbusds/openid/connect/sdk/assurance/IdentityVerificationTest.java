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

package com.nimbusds.openid.connect.sdk.assurance;


import java.util.Collections;
import java.util.Date;
import java.util.List;

import junit.framework.TestCase;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.DateWithTimeZoneOffset;
import com.nimbusds.openid.connect.sdk.assurance.evidences.IdentityEvidence;
import com.nimbusds.openid.connect.sdk.assurance.evidences.QESEvidence;


public class IdentityVerificationTest extends TestCase {
	

	public void testMinimal() throws ParseException {
		
		IdentityVerification verification = new IdentityVerification(
			IdentityTrustFramework.DE_AML,
			null,
			null,
			(List)null);
		
		assertEquals(IdentityTrustFramework.DE_AML, verification.getTrustFramework());
		
		assertNull(verification.getVerificationTime());
		assertNull(verification.getVerificationProcess());
		assertNull(verification.getEvidence());
		
		JSONObject jsonObject = verification.toJSONObject();
		assertEquals("de_aml", jsonObject.get("trust_framework"));
		assertEquals(1, jsonObject.size());
		
		verification = IdentityVerification.parse(jsonObject);
		
		assertNull(verification.getVerificationTime());
		assertNull(verification.getVerificationProcess());
		assertNull(verification.getEvidence());
	}
	
	
	public void testTrustFrameworkRequired(){
		
		try {
			new IdentityVerification(null, null, null, (List)null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The trust framework must not be null", e.getMessage());
		}
	}
	
	
	public void testFullySet() throws ParseException {
		
		
		Date now = DateUtils.fromSecondsSinceEpoch(DateUtils.toSecondsSinceEpoch(new Date())); // second precision
		
		DateWithTimeZoneOffset ts = new DateWithTimeZoneOffset(now, 60);
		
		String verificationProcess = "25c2cf21-a40e-4901-a42a-d2b6e531feee";
		QESEvidence evidence = new QESEvidence(
			new Issuer("qes-issuer"),
			"8e0d81a2-c371-4a1e-9f68-a879b4053be1",
			ts);
		
		IdentityVerification verification = new IdentityVerification(
			IdentityTrustFramework.DE_AML,
			ts,
			verificationProcess,
			Collections.singletonList((IdentityEvidence) evidence));
		
		assertEquals(IdentityTrustFramework.DE_AML, verification.getTrustFramework());
		assertEquals(ts, verification.getVerificationTime());
		assertEquals(verificationProcess, verification.getVerificationProcess());
		assertEquals(evidence, verification.getEvidence().get(0));
		
		JSONObject jsonObject = verification.toJSONObject();
		
		assertEquals(IdentityTrustFramework.DE_AML.getValue(), jsonObject.get("trust_framework"));
		assertEquals(ts.toISO8601String(), jsonObject.get("time"));
		assertEquals(verificationProcess, jsonObject.get("verification_process"));
		JSONArray evidenceArray = JSONObjectUtils.getJSONArray(jsonObject, "evidence");
		assertEquals(1, evidenceArray.size());
		QESEvidence parsedEvidence = QESEvidence.parse(JSONArrayUtils.toJSONObjectList(evidenceArray).get(0));
		assertEquals(evidence.getQESIssuer(), parsedEvidence.getQESIssuer());
		assertEquals(evidence.getQESSerialNumberString(), parsedEvidence.getQESSerialNumberString());
		assertEquals(evidence.getQESCreationTime(), parsedEvidence.getQESCreationTime());
		
		verification = IdentityVerification.parse(jsonObject);
		assertEquals(IdentityTrustFramework.DE_AML, verification.getTrustFramework());
		assertEquals(ts.toISO8601String(), verification.getVerificationTime().toISO8601String());
		assertEquals(verificationProcess, verification.getVerificationProcess());
		assertEquals(evidence.getQESIssuer(), verification.getEvidence().get(0).toQESEvidence().getQESIssuer());
		assertEquals(evidence.getQESSerialNumberString(), verification.getEvidence().get(0).toQESEvidence().getQESSerialNumberString());
		assertEquals(evidence.getQESCreationTime(), verification.getEvidence().get(0).toQESEvidence().getQESCreationTime());
	}
}
