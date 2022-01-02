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


import java.util.List;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.DateWithTimeZoneOffset;
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.Attachment;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.EmbeddedAttachment;


public class DocumentEvidenceTest extends TestCase {


	public void testMinimal()
		throws ParseException {
		
		DocumentEvidence documentEvidence = new DocumentEvidence(
			null,
			null,
			null,
			null,
			null,
			null,
			null
		);
		
		assertNull(documentEvidence.getValidationMethod());
		assertNull(documentEvidence.getVerificationMethod());
		assertNull(documentEvidence.getMethod());
		assertNull(documentEvidence.getVerifier());
		assertNull(documentEvidence.getVerificationTime());
		assertNull(documentEvidence.getDocumentDetails());
		assertNull(documentEvidence.getAttachments());
		
		JSONObject jsonObject = documentEvidence.toJSONObject();
		assertEquals(IdentityEvidenceType.DOCUMENT.getValue(), jsonObject.get("type"));
		assertEquals(1, jsonObject.size());
		
		documentEvidence = DocumentEvidence.parse(jsonObject);
		
		assertNull(documentEvidence.getValidationMethod());
		assertNull(documentEvidence.getVerificationMethod());
		assertNull(documentEvidence.getMethod());
		assertNull(documentEvidence.getVerifier());
		assertNull(documentEvidence.getVerificationTime());
		assertNull(documentEvidence.getDocumentDetails());
		assertNull(documentEvidence.getAttachments());
		
		assertEquals(documentEvidence, DocumentEvidence.parse(jsonObject));
		assertEquals(documentEvidence.hashCode(), DocumentEvidence.parse(jsonObject).hashCode());
	}
	
	
	public void testParseExampleWithAttachment()
		throws ParseException {
		
		String json = "{" +
			"  \"type\": \"document\"," +
			"  \"method\": \"pipp\"," +
			"  \"time\": \"2012-04-22T11:30Z\"," +
			"  \"document_details\": {" +
			"    \"type\": \"idcard\"," +
			"    \"issuer\": {" +
			"      \"name\": \"Stadt Augsburg\"," +
			"      \"country\": \"DE\"" +
			"    }," +
			"    \"document_number\": \"53554554\"," +
			"    \"date_of_issuance\": \"2010-03-23\"," +
			"    \"date_of_expiry\": \"2020-03-22\"" +
			"  }," +
			"  \"attachments\": [" +
			"    {" +
			"      \"desc\": \"Front of id document\"," +
			"      \"content_type\": \"image/png\"," +
			"      \"content\": \"Wkd0bWFtVnlhWFI2Wlc0Mk16VER2RFUyY0RRMWFUbDBNelJ1TlRjd31dzdaM1pTQXJaWGRsTXpNZ2RETmxDZwo=\"" +
			"    }," +
			"    {" +
			"      \"desc\": \"Back of id document\"," +
			"      \"content_type\": \"image/png\"," +
			"      \"content\": \"iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAADSFsjdkhjwhAABJRU5ErkJggg==\"" +
			"    }" +
			"  ]" +
			"}";
		
		JSONObject jsonObject = JSONObjectUtils.parse(json);
		
		DocumentEvidence documentEvidence = DocumentEvidence.parse(jsonObject);
		
		assertEquals(IdentityEvidenceType.DOCUMENT, documentEvidence.getEvidenceType());
		assertEquals(IdentityVerificationMethod.PIPP, documentEvidence.getMethod());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-22T11:30Z"), documentEvidence.getVerificationTime());
		
		DocumentDetails details = documentEvidence.getDocumentDetails();
		assertEquals(DocumentType.IDCARD, details.getType());
		assertEquals(new DocumentNumber("53554554"), details.getDocumentNumber());
		assertEquals(new SimpleDate(2010, 3, 23), details.getDateOfIssuance());
		assertEquals(new SimpleDate(2020, 3, 22), details.getDateOfExpiry());
		DocumentIssuer issuer = details.getIssuer();
		assertEquals(new Name("Stadt Augsburg"), issuer.getName());
		assertEquals("DE", issuer.getAddress().getCountry());
		assertEquals(2, issuer.toJSONObject().size());
		assertEquals(5, details.toJSONObject().size());
		
		List<Attachment> attachments = documentEvidence.getAttachments();
		assertEquals(2, attachments.size());
		
		EmbeddedAttachment frontOfIDDoc = attachments.get(0).toEmbeddedAttachment();
		assertEquals("Front of id document", frontOfIDDoc.getDescriptionString());
		assertEquals(ContentType.IMAGE_PNG, frontOfIDDoc.getContent().getType());
		assertEquals(new Base64("Wkd0bWFtVnlhWFI2Wlc0Mk16VER2RFUyY0RRMWFUbDBNelJ1TlRjd31dzdaM1pTQXJaWGRsTXpNZ2RETmxDZwo="), frontOfIDDoc.getContent().getBase64());
		
		EmbeddedAttachment backOfIDDoc = attachments.get(1).toEmbeddedAttachment();
		assertEquals("Back of id document", backOfIDDoc.getDescriptionString());
		assertEquals(ContentType.IMAGE_PNG, backOfIDDoc.getContent().getType());
		assertEquals(new Base64("iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAADSFsjdkhjwhAABJRU5ErkJggg=="), backOfIDDoc.getContent().getBase64());
	}
	
	
	public void testParseExample_idCard()
		throws ParseException {
		
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
		
		DocumentEvidence documentEvidence = DocumentEvidence.parse(jsonObject);
		
		assertEquals(IdentityEvidenceType.DOCUMENT, documentEvidence.getEvidenceType());
		assertEquals(ValidationMethodType.VPIP ,documentEvidence.getValidationMethod().getType());
		assertEquals(VerificationMethodType.PVP, documentEvidence.getVerificationMethod().getType());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-22T11:30Z"), documentEvidence.getVerificationTime());
		assertEquals(DocumentType.DE_ERP_REPLACEMENT_IDCARD, documentEvidence.getDocumentDetails().getType());
		assertEquals(new DocumentNumber("53554554"), documentEvidence.getDocumentDetails().getDocumentNumber());
		assertEquals(new SimpleDate(2010, 4, 23), documentEvidence.getDocumentDetails().getDateOfIssuance());
		assertEquals(new SimpleDate(2020, 4, 22), documentEvidence.getDocumentDetails().getDateOfExpiry());
		assertEquals(new Name("Stadt Augsburg"), documentEvidence.getDocumentDetails().getIssuer().getName());
		assertEquals("DE", documentEvidence.getDocumentDetails().getIssuer().getAddress().getCountry());
		assertNull(documentEvidence.getAttachments());
	}
	
	
	public void testParseExample_utilityStatement()
		throws ParseException {
		
		String json = "{" +
			"  \"type\": \"document\"," +
			"  \"validation_method\": {" +
			"    \"type\": \"vpip\"" +
			"  }," +
			"  \"time\": \"2012-04-22T11:30Z\"," +
			"  \"document_details\": {" +
			"    \"type\": \"utility_statement\"," +
			"    \"issuer\": {" +
			"        \"name\": \"Stadtwerke Musterstadt\"," +
			"        \"country\": \"DE\"," +
			"        \"region\": \"Niedersachsen\"," +
			"        \"street_address\": \"Energiestrasse 33\"" +
			"    }," +
			"    \"date_of_issuance\": \"2013-01-31\"" +
			"  }" +
			"}";
		
		JSONObject jsonObject = JSONObjectUtils.parse(json);
		
		DocumentEvidence documentEvidence = DocumentEvidence.parse(jsonObject);
		assertEquals(IdentityEvidenceType.DOCUMENT, documentEvidence.getEvidenceType());
		assertEquals(ValidationMethodType.VPIP, documentEvidence.getValidationMethod().getType());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-22T11:30Z"), documentEvidence.getVerificationTime());
		assertEquals(DocumentType.UTILITY_STATEMENT, documentEvidence.getDocumentDetails().getType());
		assertEquals(new SimpleDate(2013, 1, 31), documentEvidence.getDocumentDetails().getDateOfIssuance());
		assertEquals(new Name("Stadtwerke Musterstadt"), documentEvidence.getDocumentDetails().getIssuer().getName());
		assertEquals("DE", documentEvidence.getDocumentDetails().getIssuer().getAddress().getCountry());
		assertEquals("Niedersachsen", documentEvidence.getDocumentDetails().getIssuer().getAddress().getRegion());
		assertEquals("Energiestrasse 33", documentEvidence.getDocumentDetails().getIssuer().getAddress().getStreetAddress());
		assertNull(documentEvidence.getAttachments());
	}
	
	
	public void testParse_empty() {
		
		try {
			DocumentEvidence.parse(new JSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key type", e.getMessage());
		}
	}
}
