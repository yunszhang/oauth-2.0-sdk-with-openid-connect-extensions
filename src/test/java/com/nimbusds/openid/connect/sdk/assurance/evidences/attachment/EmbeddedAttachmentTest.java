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


import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.ParseException;


public class EmbeddedAttachmentTest extends TestCase {
	
	
	public static final ContentType IMAGE_JPG = new ContentType("image", "jpg");
	
	
	public static final Base64 SAMPLE_ID_CARD_JPEG = new Base64(
		"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");


	public void testLifeCycle()
		throws ParseException {
	
		String description = "John Doe ID card";
		
		EmbeddedAttachment attachment = new EmbeddedAttachment(IMAGE_JPG, SAMPLE_ID_CARD_JPEG, description);
		
		assertEquals(AttachmentType.EMBEDDED, attachment.getType());
		assertEquals(IMAGE_JPG, attachment.getContentType());
		assertEquals(SAMPLE_ID_CARD_JPEG, attachment.getContent());
		assertEquals(description, attachment.getDescriptionString());
		
		JSONObject jsonObject = attachment.toJSONObject();
		assertEquals(IMAGE_JPG.toString(), jsonObject.get("content_type"));
		assertEquals(SAMPLE_ID_CARD_JPEG.toString(), jsonObject.get("content"));
		assertEquals(description, jsonObject.get("desc"));
		assertEquals(3, jsonObject.size());
		
		attachment = EmbeddedAttachment.parse(jsonObject);
		
		assertEquals(AttachmentType.EMBEDDED, attachment.getType());
		assertEquals(IMAGE_JPG, attachment.getContentType());
		assertEquals(SAMPLE_ID_CARD_JPEG, attachment.getContent());
		assertEquals(description, attachment.getDescriptionString());
		
		assertEquals(attachment, EmbeddedAttachment.parse(jsonObject));
		assertEquals(attachment.hashCode(), EmbeddedAttachment.parse(jsonObject).hashCode());
	}


	public void testLifeCycle_noDesc()
		throws ParseException {
	
		EmbeddedAttachment attachment = new EmbeddedAttachment(IMAGE_JPG, SAMPLE_ID_CARD_JPEG, null);
		
		assertEquals(AttachmentType.EMBEDDED, attachment.getType());
		assertEquals(IMAGE_JPG, attachment.getContentType());
		assertEquals(SAMPLE_ID_CARD_JPEG, attachment.getContent());
		assertNull(attachment.getDescriptionString());
		
		JSONObject jsonObject = attachment.toJSONObject();
		assertEquals(IMAGE_JPG.toString(), jsonObject.get("content_type"));
		assertEquals(SAMPLE_ID_CARD_JPEG.toString(), jsonObject.get("content"));
		assertEquals(2, jsonObject.size());
		
		attachment = EmbeddedAttachment.parse(jsonObject);
		
		assertEquals(AttachmentType.EMBEDDED, attachment.getType());
		assertEquals(IMAGE_JPG, attachment.getContentType());
		assertEquals(SAMPLE_ID_CARD_JPEG, attachment.getContent());
		assertNull(attachment.getDescriptionString());
		
		assertEquals(attachment, EmbeddedAttachment.parse(jsonObject));
		assertEquals(attachment.hashCode(), EmbeddedAttachment.parse(jsonObject).hashCode());
	}
	
	
	public void testInequality() {
		
		EmbeddedAttachment a = new EmbeddedAttachment(IMAGE_JPG, SAMPLE_ID_CARD_JPEG, null);
		EmbeddedAttachment b = new EmbeddedAttachment(IMAGE_JPG, SAMPLE_ID_CARD_JPEG, "Some description");
		
		assertNotSame(a, b);
		assertNotSame(a.hashCode(), b.hashCode());
	}
	
	
	public void testConstructor_contentTypeMustBeDefined() {
		
		try {
			new EmbeddedAttachment(null, SAMPLE_ID_CARD_JPEG, null);
			fail();
		} catch (NullPointerException e) {
			assertEquals("The content type must not be null", e.getMessage());
		}
	}
	
	
	public void testConstructor_contentMustBeDefined() {
		
		try {
			new EmbeddedAttachment(IMAGE_JPG, null, null);
			fail();
		} catch (NullPointerException e) {
			assertEquals("The content must not be null", e.getMessage());
		}
	}
	
	
	public void testParse_missingContentType() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("content", SAMPLE_ID_CARD_JPEG.toString());
		
		try {
			EmbeddedAttachment.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key content_type", e.getMessage());
		}
	}
	
	
	public void testParse_emptyContentType() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("content_type", "");
		jsonObject.put("content", SAMPLE_ID_CARD_JPEG.toString());
		
		try {
			EmbeddedAttachment.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid content_type: Null or empty content type string", e.getMessage());
		}
	}
	
	
	public void testParse_blankContentType() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("content_type", " ");
		jsonObject.put("content", SAMPLE_ID_CARD_JPEG.toString());
		
		try {
			EmbeddedAttachment.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid content_type: Null or empty content type string", e.getMessage());
		}
	}
	
	
	public void testParse_missingContent() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("content_type", IMAGE_JPG.toString());
		
		try {
			EmbeddedAttachment.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key content", e.getMessage());
		}
	}
	
	
	public void testParse_emptyContent() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("content_type", IMAGE_JPG.toString());
		jsonObject.put("content", "");
		
		try {
			EmbeddedAttachment.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Empty or blank content", e.getMessage());
		}
	}
	
	
	public void testParse_blankContent() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("content_type", IMAGE_JPG.toString());
		jsonObject.put("content", "");
		
		try {
			EmbeddedAttachment.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Empty or blank content", e.getMessage());
		}
	}
	
	
	public void testParse_invalidContentB64()
		throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("content_type", IMAGE_JPG.toString());
		jsonObject.put("content", "{}{}{}");
		
		EmbeddedAttachment attachment = EmbeddedAttachment.parse(jsonObject);
		
		assertEquals(AttachmentType.EMBEDDED, attachment.getType());
		assertEquals(IMAGE_JPG, attachment.getContentType());
		assertEquals("{}{}{}", attachment.getContent().toString());
		assertNull(attachment.getDescriptionString());
		
		byte[] contentBytes = attachment.getContent().decode();
		assertEquals(0, contentBytes.length);
	}
}
