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


import static org.junit.Assert.assertNotEquals;

import junit.framework.TestCase;


public class IdentityEvidenceTypeTest extends TestCase {
	
	
	public void testConstants() {
		
		assertEquals("document", IdentityEvidenceType.DOCUMENT.getValue());
		assertEquals("id_document", IdentityEvidenceType.ID_DOCUMENT.getValue());
		assertEquals("electronic_record", IdentityEvidenceType.ELECTRONIC_RECORD.getValue());
		assertEquals("vouch", IdentityEvidenceType.VOUCH.getValue());
		assertEquals("utility_bill", IdentityEvidenceType.UTILITY_BILL.getValue());
		assertEquals("electronic_signature", IdentityEvidenceType.ELECTRONIC_SIGNATURE.getValue());
		assertEquals("qes", IdentityEvidenceType.QES.getValue());
	}
	
	
	public void testConstructor() {
		
		String value = "dna";
		assertEquals(value, new IdentityEvidenceType(value).getValue());
		
		assertEquals(new IdentityEvidenceType(value), new IdentityEvidenceType(value));
	}
	
	
	public void testEquality() {
		
		assertEquals(IdentityEvidenceType.UTILITY_BILL, new IdentityEvidenceType("utility_bill"));
		assertEquals(IdentityEvidenceType.UTILITY_BILL.hashCode(), new IdentityEvidenceType("utility_bill").hashCode());
	}
	
	
	public void testInequality() {
		
		assertNotEquals(IdentityEvidenceType.UTILITY_BILL, IdentityEvidenceType.ELECTRONIC_SIGNATURE);
		assertNotEquals(IdentityEvidenceType.UTILITY_BILL.hashCode(), IdentityEvidenceType.ELECTRONIC_SIGNATURE.hashCode());
	}
}
