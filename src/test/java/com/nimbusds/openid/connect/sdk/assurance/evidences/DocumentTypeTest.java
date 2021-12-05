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


public class DocumentTypeTest extends TestCase {


	public void testConstants() {
		
		assertEquals("idcard", DocumentType.IDCARD.getValue());
		assertEquals("passport", DocumentType.PASSPORT.getValue());
		assertEquals("driving_permit", DocumentType.DRIVING_PERMIT.getValue());
		assertEquals("residence_permit", DocumentType.RESIDENCE_PERMIT.getValue());
		assertEquals("de_idcard_foreigners", DocumentType.DE_IDCARD_FOREIGNERS.getValue());
		assertEquals("de_emergency_idcard", DocumentType.DE_EMERGENCY_IDCARD.getValue());
		assertEquals("de_erp", DocumentType.DE_ERP.getValue());
		assertEquals("de_erp_replacement_idcard", DocumentType.DE_ERP_REPLACEMENT_IDCARD.getValue());
		assertEquals("de_idcard_refugees", DocumentType.DE_IDCARD_REFUGEES.getValue());
		assertEquals("de_idcard_apatrids", DocumentType.DE_IDCARD_APATRIDS.getValue());
		assertEquals("de_certificate_of_suspension_of_deportation", DocumentType.DE_CERTIFICATE_OF_SUSPENSION_OF_DEPORTATION.getValue());
		assertEquals("de_permission_to_reside", DocumentType.DE_PERMISSION_TO_RESIDE.getValue());
		assertEquals("de_replacement_idcard", DocumentType.DE_REPLACEMENT_IDCARD.getValue());
		assertEquals("jp_drivers_license", DocumentType.JP_DRIVERS_LICENSE.getValue());
		assertEquals("jp_residency_card_for_foreigner", DocumentType.JP_RESIDENCY_CARD_FOR_FOREIGNER.getValue());
		assertEquals("jp_individual_number_card", DocumentType.JP_INDIVIDUAL_NUMBER_CARD.getValue());
		assertEquals("jp_permanent_residency_card_for_foreigner", DocumentType.JP_PERMANENT_RESIDENCY_CARD_FOR_FOREIGNER.getValue());
		assertEquals("jp_health_insurance_card", DocumentType.JP_HEALTH_INSURANCE_CARD.getValue());
		assertEquals("jp_residency_card", DocumentType.JP_RESIDENCY_CARD.getValue());
		assertEquals("bank_statement", DocumentType.BANK_STATEMENT.getValue());
		assertEquals("utility_statement", DocumentType.UTILITY_STATEMENT.getValue());
		assertEquals("mortgage_statement", DocumentType.MORTGAGE_STATEMENT.getValue());
		assertEquals("loan_statement", DocumentType.LOAN_STATEMENT.getValue());
		assertEquals("tax_statement", DocumentType.TAX_STATEMENT.getValue());
		assertEquals("social_security_statement", DocumentType.SOCIAL_SECURITY_STATEMENT.getValue());
		assertEquals("pilot_permit", DocumentType.PILOT_PERMIT.getValue());
		assertEquals("birth_certificate", DocumentType.BIRTH_CERTIFICATE.getValue());
		assertEquals("adoption_certificate", DocumentType.ADOPTION_CERTIFICATE.getValue());
		assertEquals("marriage_certificate", DocumentType.MARRIAGE_CERTIFICATE.getValue());
		assertEquals("gender_certificate", DocumentType.GENDER_CERTIFICATE.getValue());
		assertEquals("firearm_permit", DocumentType.FIREARM_PERMIT.getValue());
		assertEquals("education_certificate", DocumentType.EDUCATION_CERTIFICATE.getValue());
		assertEquals("visa", DocumentType.VISA.getValue());
		assertEquals("military_id", DocumentType.MILITARY_ID.getValue());
		assertEquals("voter_id", DocumentType.VOTER_ID.getValue());
	}
	
	
	public void testEqualityAndHashCode() {
		
		assertEquals(new DocumentType("idcard"), DocumentType.IDCARD);
		assertEquals(new DocumentType("idcard").hashCode(), DocumentType.IDCARD.hashCode());
	}
}
