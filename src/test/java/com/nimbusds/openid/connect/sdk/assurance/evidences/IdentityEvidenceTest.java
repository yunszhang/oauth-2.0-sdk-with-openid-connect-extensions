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


import static org.junit.Assert.*;

import net.minidev.json.JSONObject;
import org.junit.Test;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.DateWithTimeZoneOffset;
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha2CountryCode;
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha3CountryCode;


public class IdentityEvidenceTest {
	
	
	@Test
	public void parseDocumentExample() throws ParseException {
		
		String json = "{" +
			"  \"type\": \"document\"," +
			"  \"validation_method\": {" +
			"    \"type\": \"vpip\"" +
			"  }," +
			"  \"verification_method\": {" +
			"    \"type\": \"pvp\"" +
			"  }," +
			"  \"time\": \"2012-04-22T11:30Z\"," +
			"  \"document_details\": {" +
			"    \"type\": \"de_erp_replacement_idcard\"," +
			"    \"issuer\": {" +
			"      \"name\": \"Stadt Augsburg\"," +
			"      \"country\": \"DE\"" +
			"    }," +
			"    \"document_number\": \"53554554\"," +
			"    \"date_of_issuance\": \"2010-04-23\"," +
			"    \"date_of_expiry\": \"2020-04-22\"" +
			"  }" +
			"}";
		
		JSONObject jsonObject = JSONObjectUtils.parse(json);
		
		DocumentEvidence evidence = IdentityEvidence.parse(jsonObject).toDocumentEvidence();
		
		assertEquals(IdentityEvidenceType.DOCUMENT, evidence.getEvidenceType());
		assertEquals(ValidationMethodType.VPIP ,evidence.getValidationMethod().getType());
		assertEquals(VerificationMethodType.PVP, evidence.getVerificationMethod().getType());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-22T11:30Z"), evidence.getVerificationTime());
		assertEquals(DocumentType.DE_ERP_REPLACEMENT_IDCARD, evidence.getDocumentDetails().getType());
		assertEquals(new DocumentNumber("53554554"), evidence.getDocumentDetails().getDocumentNumber());
		assertEquals(new SimpleDate(2010, 4, 23), evidence.getDocumentDetails().getDateOfIssuance());
		assertEquals(new SimpleDate(2020, 4, 22), evidence.getDocumentDetails().getDateOfExpiry());
		assertEquals(new Name("Stadt Augsburg"), evidence.getDocumentDetails().getIssuer().getName());
		assertEquals("DE", evidence.getDocumentDetails().getIssuer().getAddress().getCountry());
		assertNull(evidence.getAttachments());
	}
	
	
	@Test
	public void parseIDDocumentExample() throws ParseException {
		
		String json = "{" +
			"\"type\":\"id_document\"," +
			"\"method\":\"pipp\"," +
			"\"document\":{" +
			"	\"number\":\"123456\"," +
			"	\"date_of_issuance\":\"2019-12-01\"," +
			"	\"date_of_expiry\":\"2029-11-30\"," +
			"	\"type\":\"idcard\"," +
			"	\"issuer\":{" +
			"		\"country\":\"BG\"," +
			"		\"name\":\"ID issuer\"" +
			"		}" +
			"	}" +
			"}";
		
		IDDocumentEvidence evidence = IdentityEvidence.parse(JSONObjectUtils.parse(json)).toIDDocumentEvidence();
		assertEquals(IdentityEvidenceType.ID_DOCUMENT, evidence.getEvidenceType());
		assertEquals(IdentityVerificationMethod.PIPP, evidence.getVerificationMethod());
		assertEquals(IDDocumentType.IDCARD, evidence.getIdentityDocument().getType());
		assertEquals(new SimpleDate(2019, 12, 1), evidence.getIdentityDocument().getDateOfIssuance());
		assertEquals(new SimpleDate(2029, 11, 30), evidence.getIdentityDocument().getDateOfExpiry());
		assertEquals("123456", evidence.getIdentityDocument().getNumber());
		assertEquals(new ISO3166_1Alpha2CountryCode("BG"), evidence.getIdentityDocument().getIssuerCountry());
		assertEquals("ID issuer", evidence.getIdentityDocument().getIssuerName());
	}
	
	
	@Test
	public void parseElectronicRecord() throws ParseException {
		
		String json = "{" +
			"  \"type\": \"electronic_record\"," +
			"  \"validation_method\": {" +
			"    \"type\": \"data\"" +
			"  }," +
			"  \"verification_method\": {" +
			"    \"type\": \"token\"" +
			"  }," +
			"  \"time\": \"2021-02-15T16:51Z\"," +
			"  \"record\": {" +
			"    \"type\": \"population_register\"," +
			"    \"source\": {" +
			"        \"name\": \"Skatteverket\"," +
			"        \"country\": \"Sverige\"," +
			"        \"country_code\": \"SWE\"" +
			"    }," +
			"    \"personal_number\": \"4901224131\"," +
			"    \"created_at\": \"1979-01-22T12:15Z\"" +
			"  }" +
			"}";
		
		ElectronicRecordEvidence evidence = IdentityEvidence.parse(JSONObjectUtils.parse(json)).toElectronicRecordEvidence();
		assertEquals(IdentityEvidenceType.ELECTRONIC_RECORD, evidence.getEvidenceType());
		assertEquals(ValidationMethodType.DATA, evidence.getValidationMethod().getType());
		assertEquals(VerificationMethodType.TOKEN, evidence.getVerificationMethod().getType());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2021-02-15T16:51Z"), evidence.getVerificationTime());
		assertEquals(ElectronicRecordType.POPULATION_REGISTER, evidence.getRecordDetails().getType());
		assertEquals(new Name("Skatteverket"), evidence.getRecordDetails().getSource().getName());
		assertEquals("Sverige", evidence.getRecordDetails().getSource().getAddress().getCountry());
		assertEquals(new ISO3166_1Alpha3CountryCode("SWE"), evidence.getRecordDetails().getSource().getCountryCode());
		assertEquals(new PersonalNumber("4901224131"), evidence.getRecordDetails().getPersonalNumber());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("1979-01-22T12:15Z"), evidence.getRecordDetails().getCreatedAt());
	}
	
	@Test
	public void parseElectronicSignatureExample() throws ParseException {
		
		String json = "{" +
			"\"type\":\"electronic_signature\"," +
			"\"signature_type\":\"QES\"," +
			"\"issuer\":\"QES issuer\"," +
			"\"serial_number\":\"6efe7fa4-91d8-4821-9859-eaab40f321b6\"," +
			"\"created_at\":\"2012-04-23T18:25:00Z\"" +
		"}";
		
		ElectronicSignatureEvidence evidence = IdentityEvidence.parse(JSONObjectUtils.parse(json)).toElectronicSignatureEvidence();
		assertEquals(IdentityEvidenceType.ELECTRONIC_SIGNATURE, evidence.getEvidenceType());
		assertEquals(new SignatureType("QES"), evidence.getSignatureType());
		assertEquals(new Issuer("QES issuer"), evidence.getIssuer());
		assertEquals(new SerialNumber("6efe7fa4-91d8-4821-9859-eaab40f321b6"), evidence.getCertificateSerialNumber());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-23T18:25:00Z"), evidence.getCreationTime());
	}
	
	
	@Test
	public void parseQESExample() throws ParseException {
		
		String json = "{" +
			"\"created_at\":\"2021-12-25T14:04:01+02:00\"," +
			"\"serial_number\":\"6efe7fa4-91d8-4821-9859-eaab40f321b6\"," +
			"\"type\":\"qes\"," +
			"\"issuer\":\"QES issuer\"" +
			"}";
		
		QESEvidence evidence = IdentityEvidence.parse(JSONObjectUtils.parse(json)).toQESEvidence();
		assertEquals(IdentityEvidenceType.QES, evidence.getEvidenceType());
		assertEquals(new Issuer("QES issuer"), evidence.getQESIssuer());
		assertEquals("6efe7fa4-91d8-4821-9859-eaab40f321b6", evidence.getQESSerialNumberString());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2021-12-25T14:04:01+02:00"), evidence.getQESCreationTime());
	}
	
	
	@Test
	public void parseUtilityBillExample() throws ParseException {
		
		String json = "{" +
			"  \"type\": \"utility_bill\"," +
			"  \"provider\": {" +
			"    \"name\": \"Stadtwerke Musterstadt\"," +
			"    \"country\": \"DE\"," +
			"    \"region\": \"Niedersachsen\"," +
			"    \"street_address\": \"Energiestrasse 33\"" +
			"  }," +
			"  \"date\": \"2013-01-31\"" +
			"}";
		
		UtilityBillEvidence evidence = IdentityEvidence.parse(JSONObjectUtils.parse(json)).toUtilityBillEvidence();
		assertEquals(IdentityEvidenceType.UTILITY_BILL, evidence.getEvidenceType());
		assertEquals("Stadtwerke Musterstadt", evidence.getUtilityProviderName());
		assertEquals("DE", evidence.getUtilityProviderAddress().getCountry());
		assertEquals("Niedersachsen", evidence.getUtilityProviderAddress().getRegion());
		assertEquals("Energiestrasse 33", evidence.getUtilityProviderAddress().getStreetAddress());
		assertEquals(new SimpleDate(2013, 1, 31), evidence.getUtilityBillDate());
	}
	
	
	@Test
	public void parseUnknownType() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("type", "some-unsupported-type");
		
		try {
			IdentityEvidence.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Unsupported type: some-unsupported-type", e.getMessage());
		}
	}
	
	
	@Test
	public void parseEmpty() {
		
		try {
			IdentityEvidence.parse(new JSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key type", e.getMessage());
		}
	}
}
