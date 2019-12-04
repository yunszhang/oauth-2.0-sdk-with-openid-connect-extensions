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
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha2CountryCode;


public class IDDocumentEvidenceTest extends TestCase {
	
	
	public void testArgRequirement() {
		
		try {
			new IDDocumentEvidence(null, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The verification method must not be null", e.getMessage());
		}
		
		try {
			new IDDocumentEvidence(IdentityVerificationMethod.PIPP, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The identity document description must not be null", e.getMessage());
		}
	}
	
	
	public void testMinimal() throws ParseException {
		
		IDDocumentDescription idDoc = new IDDocumentDescription(
			IDDocumentType.IDCARD,
			"123456",
			"ID issuer",
			new ISO3166_1Alpha2CountryCode("BG"),
			new SimpleDate(2019, 12, 1),
			new SimpleDate(2029, 11, 30)
		);
		
		IDDocumentEvidence evidence = new IDDocumentEvidence(IdentityVerificationMethod.PIPP, null, null, idDoc);
		
		assertEquals(IdentityEvidenceType.ID_DOCUMENT, evidence.getEvidenceType());
		assertEquals(IdentityVerificationMethod.PIPP, evidence.getVerificationMethod());
		assertNull(evidence.getVerifier());
		assertNull(evidence.getVerificationTime());
		assertEquals(idDoc, evidence.getIdentityDocument());
		
		JSONObject jsonObject = evidence.toJSONObject();
		
		evidence = IDDocumentEvidence.parse(jsonObject);
		
		assertEquals(IdentityEvidenceType.ID_DOCUMENT, evidence.getEvidenceType());
		assertEquals(IdentityVerificationMethod.PIPP, evidence.getVerificationMethod());
		assertNull(evidence.getVerifier());
		assertNull(evidence.getVerificationTime());
		assertEquals(idDoc, evidence.getIdentityDocument());
	}
}
