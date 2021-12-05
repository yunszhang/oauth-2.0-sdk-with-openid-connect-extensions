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

import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


public class ExternalAttachmentTest extends TestCase {


	public void testMinimal()
		throws URISyntaxException, ParseException {
		
		URI url = new URI("https://example.com/attachments/4Ag8IpOf95");
		Digest digest = new Digest(HashAlgorithm.SHA_256, new Base64("i3O7U79LiyKmmesIgULKT2Q8LAxNO0CpwJVcbepaYf8"));
		
		ExternalAttachment attachment = new ExternalAttachment(
			url,
			null,
			0L,
			digest,
			null
		);
		
		assertEquals(url, attachment.getURL());
		assertNull(attachment.getBearerAccessToken());
		assertEquals(0L, attachment.getExpiresIn());
		assertEquals(digest, attachment.getDigest());
		assertNull(attachment.getDescriptionString());
		
		JSONObject jsonObject = attachment.toJSONObject();
		assertEquals(url.toString(), jsonObject.get("url"));
		JSONObject digestJSONObject = JSONObjectUtils.getJSONObject(jsonObject, "digest");
		assertEquals(digest.getHashAlgorithm().getValue(), digestJSONObject.get("alg"));
		assertEquals(digest.getValue().toString(), digestJSONObject.get("value"));
		assertEquals(2, digestJSONObject.size());
		
		assertEquals(2, jsonObject.size());
		
		attachment = ExternalAttachment.parse(jsonObject);
		
		assertEquals(url, attachment.getURL());
		assertNull(attachment.getBearerAccessToken());
		assertEquals(0L, attachment.getExpiresIn());
		assertEquals(digest, attachment.getDigest());
		assertNull(attachment.getDescriptionString());
	}


	public void testWithAccessTokenNoExpiration()
		throws URISyntaxException, ParseException {
		
		URI url = new URI("https://example.com/attachments/4Ag8IpOf95");
		Digest digest = new Digest(HashAlgorithm.SHA_256, new Base64("i3O7U79LiyKmmesIgULKT2Q8LAxNO0CpwJVcbepaYf8"));
		BearerAccessToken token = new BearerAccessToken("ksj3n283dke");
		
		ExternalAttachment attachment = new ExternalAttachment(
			url,
			token,
			0L,
			digest,
			null
		);
		
		assertEquals(url, attachment.getURL());
		assertEquals(token, attachment.getBearerAccessToken());
		assertEquals(0L, attachment.getExpiresIn());
		assertEquals(digest, attachment.getDigest());
		assertNull(attachment.getDescriptionString());
		
		JSONObject jsonObject = attachment.toJSONObject();
		assertEquals(url.toString(), jsonObject.get("url"));
		assertEquals(token.getValue(), jsonObject.get("access_token"));
		JSONObject digestJSONObject = JSONObjectUtils.getJSONObject(jsonObject, "digest");
		assertEquals(digest.getHashAlgorithm().getValue(), digestJSONObject.get("alg"));
		assertEquals(digest.getValue().toString(), digestJSONObject.get("value"));
		assertEquals(2, digestJSONObject.size());
		
		assertEquals(3, jsonObject.size());
		
		attachment = ExternalAttachment.parse(jsonObject);
		
		assertEquals(url, attachment.getURL());
		assertEquals(token, attachment.getBearerAccessToken());
		assertEquals(0L, attachment.getExpiresIn());
		assertEquals(digest, attachment.getDigest());
		assertNull(attachment.getDescriptionString());
	}


	public void testFullySet()
		throws URISyntaxException, ParseException {
		
		URI url = new URI("https://example.com/attachments/4Ag8IpOf95");
		Digest digest = new Digest(HashAlgorithm.SHA_256, new Base64("i3O7U79LiyKmmesIgULKT2Q8LAxNO0CpwJVcbepaYf8"));
		BearerAccessToken token = new BearerAccessToken("ksj3n283dke");
		String description = "Front of ID document";
		
		ExternalAttachment attachment = new ExternalAttachment(
			url,
			token,
			60L,
			digest,
			description
		);
		
		assertEquals(url, attachment.getURL());
		assertEquals(token, attachment.getBearerAccessToken());
		assertEquals(60L, attachment.getExpiresIn());
		assertEquals(digest, attachment.getDigest());
		assertEquals(description, attachment.getDescriptionString());
		
		JSONObject jsonObject = attachment.toJSONObject();
		assertEquals(url.toString(), jsonObject.get("url"));
		assertEquals(token.getValue(), jsonObject.get("access_token"));
		assertEquals(60L, jsonObject.get("expires_in"));
		JSONObject digestJSONObject = JSONObjectUtils.getJSONObject(jsonObject, "digest");
		assertEquals(digest.getHashAlgorithm().getValue(), digestJSONObject.get("alg"));
		assertEquals(digest.getValue().toString(), digestJSONObject.get("value"));
		assertEquals(2, digestJSONObject.size());
		assertEquals(description, jsonObject.get("desc"));
		assertEquals(5, jsonObject.size());
		
		attachment = ExternalAttachment.parse(jsonObject);
		
		assertEquals(url, attachment.getURL());
		assertEquals(token, attachment.getBearerAccessToken());
		assertEquals(60L, attachment.getBearerAccessToken().getLifetime());
		assertEquals(60L, attachment.getExpiresIn());
		assertEquals(digest, attachment.getDigest());
		assertEquals(description, attachment.getDescriptionString());
	}
	
	
	public void testParse_expiresInMustBePositive() {
	
		String json = 
			"{" +
			"  \"desc\": \"Front of id document\"," +
			"  \"digest\": {" +
			"    \"alg\": \"SHA-256\"," +
			"    \"value\": \"nVW19w6EVNWNQ8fmRCxrxqw4xLUs+T8eI0tpjZo820Bc\"" +
			"  }," +
			"  \"url\": \"https://example.com/attachments/pGL9yz4hZQ\"," +
			"  \"access_token\": \"ksj3n283dke\"," +
			"  \"expires_in\": 0" + // zero illegal
			"}";
		
		try {
			ExternalAttachment.parse(JSONObjectUtils.parse(json));
			fail();
		} catch (ParseException e) {
			assertEquals("The expires_in parameter must be a positive integer", e.getMessage());
		}
	}
	
	
	public void testParse_empty() {
		
		try {
			ExternalAttachment.parse(new JSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key url", e.getMessage());
		}
	}
}
