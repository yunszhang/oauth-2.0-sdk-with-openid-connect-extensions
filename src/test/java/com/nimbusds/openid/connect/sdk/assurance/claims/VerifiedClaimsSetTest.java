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

package com.nimbusds.openid.connect.sdk.assurance.claims;


import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.assurance.IdentityTrustFramework;
import com.nimbusds.openid.connect.sdk.assurance.IdentityVerification;
import com.nimbusds.openid.connect.sdk.assurance.evidences.*;
import com.nimbusds.openid.connect.sdk.claims.PersonClaims;


public class VerifiedClaimsSetTest extends TestCase {
	
	
	private static final IdentityVerification createSampleVerification() {
		
		return new IdentityVerification(
			IdentityTrustFramework.DE_AML,
			null,
			null,
			null);
	}
	
	
	private static final PersonClaims createSampleClaims() {
		
		PersonClaims claims = new PersonClaims();
		claims.setName("Alice Adams");
		return claims;
	}
	
	
	public void testConstructor_argRequirement() {
		
		try {
			new VerifiedClaimsSet(null, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The verification must not be null", e.getMessage());
		}
		
		try {
			new VerifiedClaimsSet(createSampleVerification(), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The claims must not be null", e.getMessage());
		}
	}
	
	
	public void testMethods() throws ParseException {
		
		IdentityVerification verification = createSampleVerification();
		PersonClaims sampleClaims = createSampleClaims();
		
		VerifiedClaimsSet set = new VerifiedClaimsSet(verification, sampleClaims);
		
		assertEquals(verification, set.getVerification());
		assertEquals(sampleClaims.toJSONObject(), set.getClaimsSet().toJSONObject());
		
		JSONObject jsonObject = set.toJSONObject();
		assertEquals(2, jsonObject.size());
		
		set = VerifiedClaimsSet.parse(JSONObjectUtils.parse(set.toJSONString()));
		
		assertEquals(verification.toJSONObject(), set.getVerification().toJSONObject());
		assertEquals(sampleClaims.toJSONObject(), set.getClaimsSet().toJSONObject());
	}
	
	
	// https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html#id-document-1
	public void testParseExample_idDocument()
		throws Exception {
		
		String json = "{  " +
//			"   \"verified_claims\":{  " +
			"      \"verification\":{  " +
			"         \"trust_framework\":\"de_aml\"," +
			"         \"time\":\"2012-04-23T18:25:43.511+01\"," +
			"         \"verification_process\":\"676q3636461467647q8498785747q487\"," +
			"         \"evidence\":[  " +
			"            {  " +
			"               \"type\":\"id_document\"," +
			"               \"method\":\"pipp\"," +
			"               \"document\":{  " +
			"                  \"type\":\"idcard\"," +
			"                  \"issuer\":{  " +
			"                     \"name\":\"Stadt Augsburg\"," +
			"                     \"country\":\"DE\"" +
			"                  }," +
			"                  \"number\":\"53554554\"," +
			"                  \"date_of_issuance\":\"2012-04-23\"," +
			"                  \"date_of_expiry\":\"2022-04-22\"" +
			"               }" +
			"            }" +
			"         ]" +
			"      }," +
			"      \"claims\":{  " +
			"         \"given_name\":\"Max\"," +
			"         \"family_name\":\"Meier\"," +
			"         \"birthdate\":\"1956-01-28\"," +
			"         \"birthplace\":{  " +
			"            \"country\":\"DE\"," +
			"            \"locality\":\"Musterstadt\"" +
			"         }," +
			"         \"nationalities\":[\"DE\"]," +
			"         \"address\":{  " +
			"            \"locality\":\"Maxstadt\"," +
			"            \"postal_code\":\"12344\"," +
			"            \"country\":\"DE\"," +
			"            \"street_address\":\"An der Sanddüne 22\"" +
			"         }" +
			"      }" +
//			"   }" +
			"}";
		
		VerifiedClaimsSet verifiedClaimsSet = VerifiedClaimsSet.parse(JSONObjectUtils.parse(json));
		
		IdentityVerification verification = verifiedClaimsSet.getVerification();
		assertEquals(IdentityTrustFramework.DE_AML, verification.getTrustFramework());
		assertEquals("2012-04-23T18:25:43+01:00", verification.getVerificationTime().toISO8601String());
		assertEquals("676q3636461467647q8498785747q487", verification.getVerificationProcess());
		
		IDDocumentEvidence idDocumentEvidence = verification.getEvidence().get(0).toIDDocumentEvidence();
		assertEquals(1, verification.getEvidence().size());
		assertEquals(IdentityEvidenceType.ID_DOCUMENT, idDocumentEvidence.getEvidenceType());
		assertEquals(IdentityVerificationMethod.PIPP, idDocumentEvidence.getVerificationMethod());
		IDDocumentDescription idDoc = idDocumentEvidence.getIdentityDocument();
		assertEquals(IDDocumentType.IDCARD, idDoc.getType());
		assertEquals("Stadt Augsburg", idDoc.getIssuerName());
		assertEquals("DE", idDoc.getIssuerCountry().getValue());
		assertEquals("53554554", idDoc.getNumber());
		assertEquals("2012-04-23", idDoc.getDateOfIssuance().toISO8601String());
		assertEquals("2022-04-22", idDoc.getDateOfExpiry().toISO8601String());
		
		PersonClaims claimsSet = verifiedClaimsSet.getClaimsSet();
		assertEquals("Max", claimsSet.getGivenName());
		assertEquals("Meier", claimsSet.getFamilyName());
		assertEquals("1956-01-28", claimsSet.getBirthdate());
		Birthplace birthplace = claimsSet.getBirthplace();
		assertEquals("DE", birthplace.getCountry().getValue());
		assertEquals("Musterstadt", birthplace.getLocality());
		assertNull(birthplace.getRegion());
		assertEquals("DE", claimsSet.getNationalities().get(0).getValue());
		assertEquals(1, claimsSet.getNationalities().size());
		assertEquals("Maxstadt", claimsSet.getAddress().getLocality());
		assertEquals("12344", claimsSet.getAddress().getPostalCode());
		assertEquals("DE", claimsSet.getAddress().getCountry());
		assertEquals("An der Sanddüne 22", claimsSet.getAddress().getStreetAddress());
	}
	
	
	// https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html#id-document-1
	public void testParseExample_idDocument_plus_utilityBill()
		throws ParseException {
		
		String json = "{  " +
			"      \"verification\":{  " +
			"         \"trust_framework\":\"de_aml\"," +
			"         \"time\":\"2012-04-23T18:25:43.511+01\"," +
			"         \"verification_process\":\"676q3636461467647q8498785747q487\"," +
			"         \"evidence\":[  " +
			"            {  " +
			"               \"type\":\"id_document\"," +
			"               \"method\":\"pipp\"," +
			"               \"document\":{  " +
			"                  \"type\":\"de_erp_replacement_idcard\"," +
			"                  \"issuer\":{  " +
			"                     \"name\":\"Stadt Augsburg\"," +
			"                     \"country\":\"DE\"" +
			"                  }," +
			"                  \"number\":\"53554554\"," +
			"                  \"date_of_issuance\":\"2012-04-23\"," +
			"                  \"date_of_expiry\":\"2022-04-22\"" +
			"               }" +
			"            }," +
			"            {  " +
			"               \"type\":\"utility_bill\"," +
			"               \"provider\":{  " +
			"                  \"name\":\"Stadtwerke Musterstadt\"," +
			"                  \"country\":\"DE\"," +
			"                  \"region\":\"Thüringen\"," +
			"                  \"street_address\":\"Energiestrasse 33\"" +
			"               }," +
			"               \"date\":\"2013-01-31\"" +
			"            }" +
			"         ]" +
			"      }," +
			"      \"claims\":{  " +
			"         \"given_name\":\"Max\"," +
			"         \"family_name\":\"Meier\"," +
			"         \"birthdate\":\"1956-01-28\"," +
			"         \"birthplace\":{  " +
			"            \"country\":\"DE\"," +
			"            \"locality\":\"Musterstadt\"" +
			"         }," +
			"         \"nationalities\":[\"DE\"]," +
			"         \"address\":{  " +
			"            \"locality\":\"Maxstadt\"," +
			"            \"postal_code\":\"12344\"," +
			"            \"country\":\"DE\"," +
			"            \"street_address\":\"An der Sanddüne 22\"" +
			"         }" +
			"      }" +
			"   }";
		
		VerifiedClaimsSet verifiedClaimsSet = VerifiedClaimsSet.parse(JSONObjectUtils.parse(json));
		
		IdentityVerification verification = verifiedClaimsSet.getVerification();
		assertEquals(IdentityTrustFramework.DE_AML, verification.getTrustFramework());
		assertEquals("2012-04-23T18:25:43+01:00", verification.getVerificationTime().toISO8601String());
		assertEquals("676q3636461467647q8498785747q487", verification.getVerificationProcess());
		
		IDDocumentEvidence idDocumentEvidence = verification.getEvidence().get(0).toIDDocumentEvidence();
		assertEquals(IdentityEvidenceType.ID_DOCUMENT, idDocumentEvidence.getEvidenceType());
		assertEquals(IdentityVerificationMethod.PIPP, idDocumentEvidence.getVerificationMethod());
		IDDocumentDescription idDoc = idDocumentEvidence.getIdentityDocument();
		assertEquals(IDDocumentType.DE_ERP_REPLACEMENT_IDCARD, idDoc.getType());
		assertEquals("Stadt Augsburg", idDoc.getIssuerName());
		assertEquals("DE", idDoc.getIssuerCountry().getValue());
		assertEquals("53554554", idDoc.getNumber());
		assertEquals("2012-04-23", idDoc.getDateOfIssuance().toISO8601String());
		assertEquals("2022-04-22", idDoc.getDateOfExpiry().toISO8601String());
		
		UtilityBillEvidence utilityBillEvidence = verification.getEvidence().get(1).toUtilityBillEvidence();
		assertEquals("Stadtwerke Musterstadt", utilityBillEvidence.getUtilityProviderName());
		assertEquals("DE", utilityBillEvidence.getUtilityProviderAddress().getCountry());
		assertEquals("Thüringen", utilityBillEvidence.getUtilityProviderAddress().getRegion());
		assertEquals("Energiestrasse 33", utilityBillEvidence.getUtilityProviderAddress().getStreetAddress());
		assertEquals("2013-01-31", utilityBillEvidence.getUtilityBillDate().toISO8601String());
		
		assertEquals(2, verification.getEvidence().size());
		
		PersonClaims claimsSet = verifiedClaimsSet.getClaimsSet();
		assertEquals("Max", claimsSet.getGivenName());
		assertEquals("Meier", claimsSet.getFamilyName());
		assertEquals("1956-01-28", claimsSet.getBirthdate());
		Birthplace birthplace = claimsSet.getBirthplace();
		assertEquals("DE", birthplace.getCountry().getValue());
		assertEquals("Musterstadt", birthplace.getLocality());
		assertNull(birthplace.getRegion());
		assertEquals("DE", claimsSet.getNationalities().get(0).getValue());
		assertEquals(1, claimsSet.getNationalities().size());
		assertEquals("Maxstadt", claimsSet.getAddress().getLocality());
		assertEquals("12344", claimsSet.getAddress().getPostalCode());
		assertEquals("DE", claimsSet.getAddress().getCountry());
		assertEquals("An der Sanddüne 22", claimsSet.getAddress().getStreetAddress());
	}
	
	
	// TODO https://bitbucket.org/openid/connect/issues/1132/assurance-63-notified-eid-system-eidas
	public void testParseExample_QES()
		throws Exception {
		
		
	}
}
