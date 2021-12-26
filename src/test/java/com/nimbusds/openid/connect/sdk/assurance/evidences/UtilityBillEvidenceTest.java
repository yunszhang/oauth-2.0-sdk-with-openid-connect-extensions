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


import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.DateWithTimeZoneOffset;
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.Attachment;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.EmbeddedAttachment;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.EmbeddedAttachmentTest;
import com.nimbusds.openid.connect.sdk.claims.Address;


public class UtilityBillEvidenceTest extends TestCase {
	
	
	public void testMinimal_deprecatedConstructor() throws ParseException {
		
		UtilityBillEvidence evidence = new UtilityBillEvidence(null, null, null);
		
		assertNull(evidence.getUtilityProviderName());
		assertNull(evidence.getUtilityProviderAddress());
		assertNull(evidence.getUtilityBillDate());
		
		JSONObject jsonObject = evidence.toJSONObject();
		assertEquals(IdentityEvidenceType.UTILITY_BILL.getValue(), jsonObject.get("type"));
		assertEquals(1, jsonObject.size());
		
		evidence = UtilityBillEvidence.parse(jsonObject);
		
		assertNull(evidence.getUtilityProviderName());
		assertNull(evidence.getUtilityProviderAddress());
		assertNull(evidence.getUtilityBillDate());
		
		assertEquals("Equality", evidence, UtilityBillEvidence.parse(jsonObject));
		assertEquals("Hash code", evidence.hashCode(), UtilityBillEvidence.parse(jsonObject).hashCode());
	}
	
	
	public void testMethods_deprecatedConstructor() throws ParseException {
		
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
		
		assertEquals("Equality", evidence, UtilityBillEvidence.parse(jsonObject));
		assertEquals("Hash code", evidence.hashCode(), UtilityBillEvidence.parse(jsonObject).hashCode());
	}
	
	
	public void testMinimal() throws ParseException {
		
		UtilityBillEvidence evidence = new UtilityBillEvidence(null, null, null, null, null, null);
		
		assertNull(evidence.getUtilityProviderName());
		assertNull(evidence.getUtilityProviderAddress());
		assertNull(evidence.getUtilityBillDate());
		assertNull(evidence.getVerificationTime());
		assertNull(evidence.getVerificationMethod());
		
		JSONObject jsonObject = evidence.toJSONObject();
		assertEquals(IdentityEvidenceType.UTILITY_BILL.getValue(), jsonObject.get("type"));
		assertEquals(1, jsonObject.size());
		
		evidence = UtilityBillEvidence.parse(jsonObject);
		
		assertNull(evidence.getUtilityProviderName());
		assertNull(evidence.getUtilityProviderAddress());
		assertNull(evidence.getUtilityBillDate());
		assertNull(evidence.getVerificationTime());
		assertNull(evidence.getVerificationMethod());
		
		assertEquals("Equality", evidence, UtilityBillEvidence.parse(jsonObject));
		assertEquals("Hash code", evidence.hashCode(), UtilityBillEvidence.parse(jsonObject).hashCode());
	}
	
	
	public void testMethods() throws ParseException {
		
		String name = "My Provider";
		Address address = new Address();
		address.setLocality("Sofia");
		SimpleDate ts = new SimpleDate(2019, 12, 1);
		DateWithTimeZoneOffset dtz = DateWithTimeZoneOffset.parseISO8601String("2012-04-23T18:25Z");
		IdentityVerificationMethod method = IdentityVerificationMethod.ONSITE;
		
		Attachment attachment = new EmbeddedAttachment(
			EmbeddedAttachmentTest.IMAGE_JPG,
			EmbeddedAttachmentTest.SAMPLE_ID_CARD_JPEG,
			"Some description"
		);
		List<Attachment> attachments = Collections.singletonList(attachment);
		
		UtilityBillEvidence evidence = new UtilityBillEvidence(name, address, ts, dtz, method, attachments);;
		
		assertEquals(IdentityEvidenceType.UTILITY_BILL, evidence.getEvidenceType());
		assertEquals(name, evidence.getUtilityProviderName());
		assertEquals(address, evidence.getUtilityProviderAddress());
		assertEquals(ts, evidence.getUtilityBillDate());
		assertEquals(dtz, evidence.getVerificationTime());
		assertEquals(method, evidence.getVerificationMethod());
		assertEquals(attachments, evidence.getAttachments());
		
		JSONObject jsonObject = evidence.toJSONObject();
		assertEquals("utility_bill", jsonObject.get("type"));
		JSONObject providerObject = JSONObjectUtils.getJSONObject(jsonObject, "provider");
		assertEquals(name, providerObject.get("name"));
		assertEquals(address.getLocality(), providerObject.get("locality"));
		assertEquals(2, providerObject.size());
		assertEquals(ts.toISO8601String(), jsonObject.get("date"));
		assertEquals(dtz.toISO8601String(), jsonObject.get("time"));
		assertEquals(method.getValue(), jsonObject.get("method"));
		JSONArray attachmentArray = JSONObjectUtils.getJSONArray(jsonObject, "attachments");
		assertEquals(attachments, Attachment.parseList(attachmentArray));
		assertEquals(1, attachmentArray.size());
		assertEquals(6, jsonObject.size());
		
		evidence = UtilityBillEvidence.parse(jsonObject);
		
		assertEquals(IdentityEvidenceType.UTILITY_BILL, evidence.getEvidenceType());
		assertEquals(name, evidence.getUtilityProviderName());
		assertEquals(address.toJSONObject(), evidence.getUtilityProviderAddress().toJSONObject());
		assertEquals(ts, evidence.getUtilityBillDate());
		assertEquals(dtz, evidence.getVerificationTime());
		assertEquals(method, evidence.getVerificationMethod());
		assertEquals(attachments, evidence.getAttachments());
		
		assertEquals("Equality", evidence, UtilityBillEvidence.parse(jsonObject));
		assertEquals("Hash code", evidence.hashCode(), UtilityBillEvidence.parse(jsonObject).hashCode());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#section-8.8
	public void testParseExample() throws ParseException {
	
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
		
		UtilityBillEvidence evidence = UtilityBillEvidence.parse(JSONObjectUtils.parse(json));
		assertEquals(IdentityEvidenceType.UTILITY_BILL, evidence.getEvidenceType());
		assertEquals("Stadtwerke Musterstadt", evidence.getUtilityProviderName());
		assertEquals("DE", evidence.getUtilityProviderAddress().getCountry());
		assertEquals("Niedersachsen", evidence.getUtilityProviderAddress().getRegion());
		assertEquals("Energiestrasse 33", evidence.getUtilityProviderAddress().getStreetAddress());
		assertEquals(new SimpleDate(2013, 1, 31), evidence.getUtilityBillDate());
	}
}
