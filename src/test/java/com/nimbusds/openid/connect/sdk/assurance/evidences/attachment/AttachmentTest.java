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

package com.nimbusds.openid.connect.sdk.assurance.evidences.attachment;


import java.net.URI;
import java.net.URISyntaxException;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


public class AttachmentTest extends TestCase {


	public void testParse_embedded()
		throws ParseException {
		
		String json = "{" +
			"  \"desc\": \"Front of id document\"," +
			"  \"content_type\": \"image/png\"," +
			"  \"content\": \"Wkd0bWFtVnlhWFI2Wlc0Mk16VER2RFUyY0RRMWFUbDBNelJ1TlRjd31dzdaM1pTQXJaWGRsTXpNZ2RETmxDZwo=\"" +
			"}";
		
		Attachment attachment = Attachment.parse(JSONObjectUtils.parse(json));
		
		assertEquals("Front of id document", attachment.getDescriptionString());
		
		EmbeddedAttachment embeddedAttachment = attachment.toEmbeddedAttachment();
		
		assertEquals(ContentType.IMAGE_PNG, embeddedAttachment.getContentType());
		assertEquals(new Base64("Wkd0bWFtVnlhWFI2Wlc0Mk16VER2RFUyY0RRMWFUbDBNelJ1TlRjd31dzdaM1pTQXJaWGRsTXpNZ2RETmxDZwo="), embeddedAttachment.getContent());
	}
	
	
	public void testParse_external()
		throws ParseException, URISyntaxException {
		
		String json = "{" +
			"  \"desc\": \"Signed document\"," +
			"  \"digest\": {" +
			"    \"alg\": \"SHA-256\"," +
			"    \"value\": \"i3O7U79LiyKmmesIgULKT2Q8LAxNO0CpwJVcbepaYf8\"" +
			"  }," +
			"  \"url\": \"https://example.com/attachments/4Ag8IpOf95\"," +
			"  \"access_token\": null," +
			"  \"expires_in\": 30" +
			"}";
		
		Attachment attachment = Attachment.parse(JSONObjectUtils.parse(json));
		
		assertEquals("Signed document", attachment.getDescriptionString());
		
		ExternalAttachment externalAttachment = attachment.toExternalAttachment();
		
		Digest digest = externalAttachment.getDigest();
		assertEquals(HashAlgorithm.SHA_256, digest.getHashAlgorithm());
		assertEquals(new Base64("i3O7U79LiyKmmesIgULKT2Q8LAxNO0CpwJVcbepaYf8"), digest.getValue());
		
		assertEquals(new URI("https://example.com/attachments/4Ag8IpOf95"), externalAttachment.getURL());
		assertNull(externalAttachment.getBearerAccessToken());
		assertEquals(30L, externalAttachment.getExpiresIn());
	}
	
	
	public void testParse_missingParams() {
		
		try {
			Attachment.parse(new JSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing required attachment parameter(s)", e.getMessage());
		}
	}
}
