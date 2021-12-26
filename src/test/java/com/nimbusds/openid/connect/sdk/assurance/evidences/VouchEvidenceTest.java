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


import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.DateWithTimeZoneOffset;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.Attachment;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.Digest;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.ExternalAttachment;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.HashAlgorithm;


public class VouchEvidenceTest extends TestCase {


	public void testMinimal()
		throws ParseException {
		
		VouchEvidence evidence = new VouchEvidence(
			null,
			null,
			null,
			null,
			null,
			null
		);
		
		assertEquals(IdentityEvidenceType.VOUCH, evidence.getEvidenceType());
		assertNull(evidence.getValidationMethod());
		assertNull(evidence.getVerificationMethod());
		assertNull(evidence.getVerifier());
		assertNull(evidence.getVerificationTime());
		assertNull(evidence.getAttestation());
		assertNull(evidence.getAttachments());
		
		JSONObject jsonObject = evidence.toJSONObject();
		
		assertEquals(IdentityEvidenceType.VOUCH.getValue(), jsonObject.get("type"));
		assertEquals(1, jsonObject.size());
		
		evidence = VouchEvidence.parse(jsonObject);
		
		assertEquals(IdentityEvidenceType.VOUCH, evidence.getEvidenceType());
		assertNull(evidence.getValidationMethod());
		assertNull(evidence.getVerificationMethod());
		assertNull(evidence.getVerifier());
		assertNull(evidence.getVerificationTime());
		assertNull(evidence.getAttestation());
		assertNull(evidence.getAttachments());
		
		assertEquals("Equality", evidence, VouchEvidence.parse(jsonObject));
		assertEquals("Equality", evidence.hashCode(), VouchEvidence.parse(jsonObject).hashCode());
	}
	
	
	public void testFullySet()
		throws ParseException, URISyntaxException {
		
		ValidationMethod validationMethod = new ValidationMethod(ValidationMethodType.VPIP, null, null, null);
		VerificationMethod verificationMethod = new VerificationMethod(VerificationMethodType.PVP, null, null, null);
		IdentityVerifier verifier = new IdentityVerifier(new Organization("Some org"), null);
		DateWithTimeZoneOffset time = DateWithTimeZoneOffset.parseISO8601String("2012-04-22T11:30Z");
		Attestation attestation = new Attestation(
			VouchType.DIGITAL_ATTESTATION,
			new ReferenceNumber("123"),
			new PersonalNumber("456"),
			null,
			null,
			null
		);
		
		Attachment externalAttachment = new ExternalAttachment(
			new URI("https://records.example.com/e9a6581d-c829-4adf-a58d-e5441e43a679"),
			new BearerAccessToken("tieb3ueZietai2ee"),
			60L,
			new Digest(HashAlgorithm.SHA_256, new Base64("fNd59zjM4eW/wyVd7SXCMvR0dq5FJ1tFwNNVa+ThQHM=")),
			"Record link"
		);
		
		List<Attachment> attachments = Collections.singletonList(externalAttachment);
		
		VouchEvidence evidence = new VouchEvidence(
			validationMethod,
			verificationMethod,
			verifier,
			time,
			attestation,
			attachments
		);
		
		assertEquals(IdentityEvidenceType.VOUCH, evidence.getEvidenceType());
		assertEquals(validationMethod, evidence.getValidationMethod());
		assertEquals(verificationMethod, evidence.getVerificationMethod());
		assertEquals(verifier, evidence.getVerifier());
		assertEquals(time, evidence.getVerificationTime());
		assertEquals(attestation, evidence.getAttestation());
		assertEquals(attachments, evidence.getAttachments());
		
		JSONObject jsonObject = evidence.toJSONObject();
		assertEquals(IdentityEvidenceType.VOUCH.getValue(), jsonObject.get("type"));
		assertEquals(validationMethod.toJSONObject(), JSONObjectUtils.getJSONObject(jsonObject, "validation_method"));
		assertEquals(verificationMethod.toJSONObject(), JSONObjectUtils.getJSONObject(jsonObject, "verification_method"));
		assertEquals(verifier.toJSONObject(), JSONObjectUtils.getJSONObject(jsonObject, "verifier"));
		assertEquals(time.toISO8601String(), jsonObject.get("time"));
		assertEquals(attestation.toJSONObject(), JSONObjectUtils.getJSONObject(jsonObject, "attestation"));
		assertEquals(Collections.singletonList(externalAttachment.toJSONObject()), JSONObjectUtils.getJSONArray(jsonObject, "attachments"));
		assertEquals(7, jsonObject.size());
		
		evidence = VouchEvidence.parse(jsonObject);
		
		assertEquals(IdentityEvidenceType.VOUCH, evidence.getEvidenceType());
		assertEquals(validationMethod, evidence.getValidationMethod());
		assertEquals(verificationMethod, evidence.getVerificationMethod());
		assertEquals(verifier, evidence.getVerifier());
		assertEquals(time, evidence.getVerificationTime());
		assertEquals(attestation, evidence.getAttestation());
		assertEquals(attachments, evidence.getAttachments());
		
		assertEquals("Equality", evidence, VouchEvidence.parse(jsonObject));
		assertEquals("Equality", evidence.hashCode(), VouchEvidence.parse(jsonObject).hashCode());
	}
	
	
	public void testParseEmpty() {
		
		try {
			VouchEvidence.parse(new JSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key type", e.getMessage());
		}
	}
}
