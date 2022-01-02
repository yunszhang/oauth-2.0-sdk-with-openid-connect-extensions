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


import java.io.IOException;
import java.net.URI;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


public class EmbeddedAttachmentRetrievalTest {


	@Before
	public void setUp() {
		
		initJadler();
	}
	
	
	@After
	public void tearDown() {
		closeJadler();
	}
	
	
	@Test
	public void retrieveWithToken_200()
		throws Exception {
		
		String path = "/Gu1ail4a";
		URI url = new URI("http://localhost:" + port() + path);
		final BearerAccessToken accessToken = new BearerAccessToken("ahVoechohtu9bohzaici9ieph5feaf6o");
		Digest digest = Digest.compute(HashAlgorithm.SHA_256, ContentTest.SAMPLE_ID_CARD_JPEG);
		String description = "Front of document";
		
		ExternalAttachment attachment = new ExternalAttachment(
			url,
			accessToken,
			60,
			digest,
			description
		);
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo(path)
			.havingHeaderEqualTo("Authorization", accessToken.toAuthorizationHeader())
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", ContentTest.IMAGE_JPG.toString())
			.withBody(ContentTest.SAMPLE_ID_CARD_JPEG.toString());
		
		Content content = attachment.retrieveContent(250, 250);
		
		assertEquals(ContentTest.IMAGE_JPG, content.getType());
		assertEquals(ContentTest.SAMPLE_ID_CARD_JPEG, content.getBase64());
		assertEquals(description, content.getDescription());
	}
	
	
	@Test
	public void retrieveNoTokenNoDescription_200()
		throws Exception {
		
		String path = "/ahVoechohtu9bohzaici9ieph5feaf6o";
		URI url = new URI("http://localhost:" + port() + path);
		Digest digest = Digest.compute(HashAlgorithm.SHA_256, ContentTest.SAMPLE_ID_CARD_JPEG);
		
		ExternalAttachment attachment = new ExternalAttachment(
			url,
			null,
			60,
			digest,
			null
		);
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo(path)
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", ContentTest.IMAGE_JPG.toString())
			.withBody(ContentTest.SAMPLE_ID_CARD_JPEG.toString());
		
		Content content = attachment.retrieveContent(250, 250);
		
		assertEquals(ContentTest.IMAGE_JPG, content.getType());
		assertEquals(ContentTest.SAMPLE_ID_CARD_JPEG, content.getBase64());
		assertNull(content.getDescription());
	}
	
	
	@Test
	public void retrieve_missingContentInResponse()
		throws Exception {
		
		String path = "/ahVoechohtu9bohzaici9ieph5feaf6o";
		URI url = new URI("http://localhost:" + port() + path);
		Digest digest = Digest.compute(HashAlgorithm.SHA_256, ContentTest.SAMPLE_ID_CARD_JPEG);
		
		ExternalAttachment attachment = new ExternalAttachment(
			url,
			null,
			60,
			digest,
			null
		);
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo(path)
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", ContentTest.IMAGE_JPG.toString())
			.withBody("");
		
		try {
			attachment.retrieveContent(250, 250);
			fail();
		} catch (IOException e) {
			assertEquals("The HTTP response has no content: " + url, e.getMessage());
		}
	}
	
	
	@Test
	public void retrieve_missingContentTypeInResponse()
		throws Exception {
		
		String path = "/ahVoechohtu9bohzaici9ieph5feaf6o";
		URI url = new URI("http://localhost:" + port() + path);
		Digest digest = Digest.compute(HashAlgorithm.SHA_256, ContentTest.SAMPLE_ID_CARD_JPEG);
		
		ExternalAttachment attachment = new ExternalAttachment(
			url,
			null,
			60,
			digest,
			null
		);
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo(path)
			.respond()
			.withStatus(200)
			.withBody(ContentTest.SAMPLE_ID_CARD_JPEG.toString());
		
		try {
			attachment.retrieveContent(250, 250);
			fail();
		} catch (IOException e) {
			assertEquals("Missing Content-Type header in HTTP response: " + url, e.getMessage());
		}
	}
	
	
	@Test
	public void retrieve_404()
		throws Exception {
		
		String path = "/Gu1ail4a";
		URI url = new URI("http://localhost:" + port() + path);
		final BearerAccessToken accessToken = new BearerAccessToken("ahVoechohtu9bohzaici9ieph5feaf6o");
		Digest digest = Digest.compute(HashAlgorithm.SHA_256, ContentTest.SAMPLE_ID_CARD_JPEG);
		String description = "Front of document";
		
		ExternalAttachment attachment = new ExternalAttachment(
			url,
			accessToken,
			60,
			digest,
			description
		);
		
		onRequest()
			.respond()
			.withStatus(404);
		
		try{
			attachment.retrieveContent(250, 250);
			fail();
		} catch (IOException e) {
			assertEquals("Unexpected HTTP status code 404, must be [200]", e.getMessage());
		}
	}
	
	
	@Test
	public void retrieve_digestMismatch()
		throws Exception {
		
		String path = "/Gu1ail4a";
		URI url = new URI("http://localhost:" + port() + path);
		final BearerAccessToken accessToken = new BearerAccessToken("ahVoechohtu9bohzaici9ieph5feaf6o");
		Digest digest = Digest.compute(HashAlgorithm.SHA_256, ContentTest.SAMPLE_ID_CARD_JPEG);
		String description = "Front of document";
		
		ExternalAttachment attachment = new ExternalAttachment(
			url,
			accessToken,
			60,
			digest,
			description
		);
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo(path)
			.havingHeaderEqualTo("Authorization", accessToken.toAuthorizationHeader())
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", ContentTest.IMAGE_JPG.toString())
			.withBody("abc"); // invalid content
		
		try {
			attachment.retrieveContent(250, 250);
			fail();
		} catch (DigestMismatchException e) {
			assertEquals("The computed sha-256 digest for the retrieved content doesn't match the expected: " + url, e.getMessage());
		}
	}
}
