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

package com.nimbusds.openid.connect.sdk.id;


import java.net.URI;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;

import junit.framework.TestCase;

import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.oauth2.sdk.id.Subject;


public class SIVAESBasedPairwiseSubjectCodecTest extends TestCase {
	
	
	public void testWith256BitKey()
		throws Exception {
		
		int keyBitSize = 256;
		byte[] keyBytes = new byte[ByteUtils.byteLength(keyBitSize)];
		new SecureRandom().nextBytes(keyBytes);
		
		SIVAESBasedPairwiseSubjectCodec codec = new SIVAESBasedPairwiseSubjectCodec(new SecretKeySpec(keyBytes, "AES"));
		
		assertArrayEquals(keyBytes, codec.getSecretKey().getEncoded());
		
		SectorID sectorID = new SectorID(URI.create("https://example.com"));
		Subject subject = new Subject("alice");
		
		Subject pairwiseSubject = codec.encode(sectorID, subject);
		
		System.out.println("Pairwise subject (" + keyBitSize + " bit key): " + pairwiseSubject);
		
		// Repeat
		for (int i=0; i < 1000; i++) {
			assertEquals(pairwiseSubject, codec.encode(sectorID, subject));
		}
		
		assertEquals(sectorID, codec.decode(pairwiseSubject).getKey());
		assertEquals(subject, codec.decode(pairwiseSubject).getValue());
	}
	
	
	public void testWith384BitKey()
		throws Exception {
		
		int keyBitSize = 384;
		byte[] keyBytes = new byte[ByteUtils.byteLength(keyBitSize)];
		new SecureRandom().nextBytes(keyBytes);
		
		SIVAESBasedPairwiseSubjectCodec codec = new SIVAESBasedPairwiseSubjectCodec(new SecretKeySpec(keyBytes, "AES"));
		
		assertArrayEquals(keyBytes, codec.getSecretKey().getEncoded());
		
		SectorID sectorID = new SectorID(URI.create("https://example.com"));
		Subject subject = new Subject("alice");
		
		Subject pairwiseSubject = codec.encode(sectorID, subject);
		
		System.out.println("Pairwise subject (" + keyBitSize + " bit key): " + pairwiseSubject);
		
		// Repeat
		for (int i=0; i < 1000; i++) {
			assertEquals(pairwiseSubject, codec.encode(sectorID, subject));
		}
		
		assertEquals(sectorID, codec.decode(pairwiseSubject).getKey());
		assertEquals(subject, codec.decode(pairwiseSubject).getValue());
	}
	
	
	public void testWith512BitKey()
		throws Exception {
		
		int keyBitSize = 512;
		byte[] keyBytes = new byte[ByteUtils.byteLength(keyBitSize)];
		new SecureRandom().nextBytes(keyBytes);
		
		SIVAESBasedPairwiseSubjectCodec codec = new SIVAESBasedPairwiseSubjectCodec(new SecretKeySpec(keyBytes, "AES"));
		
		assertArrayEquals(keyBytes, codec.getSecretKey().getEncoded());
		
		SectorID sectorID = new SectorID(URI.create("https://example.com"));
		Subject subject = new Subject("alice");
		
		Subject pairwiseSubject = codec.encode(sectorID, subject);
		
		System.out.println("Pairwise subject (" + keyBitSize + " bit key): " + pairwiseSubject);
		
		// Repeat
		for (int i=0; i < 1000; i++) {
			assertEquals(pairwiseSubject, codec.encode(sectorID, subject));
		}
		
		assertEquals(sectorID, codec.decode(pairwiseSubject).getKey());
		assertEquals(subject, codec.decode(pairwiseSubject).getValue());
	}
	
	
	public void testUnsupportedKeyLength() {
		
		byte[] keyBytes = new byte[ByteUtils.byteLength(128)];
		new SecureRandom().nextBytes(keyBytes);
		
		try {
			new SIVAESBasedPairwiseSubjectCodec(new SecretKeySpec(keyBytes, "AES"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The SIV AES secret key length must be 256, 384 or 512 bits", e.getMessage());
		}
	}
	
	
	public void testDecryptFail() {
		
		byte[] keyBytes = new byte[ByteUtils.byteLength(256)];
		new SecureRandom().nextBytes(keyBytes);
		
		SIVAESBasedPairwiseSubjectCodec codec = new SIVAESBasedPairwiseSubjectCodec(new SecretKeySpec(keyBytes, "AES"));
		try {
			codec.decode(new Subject("abcxyzabcxyzabcxyzabcxyzabcxyz"));
			fail();
		} catch (InvalidPairwiseSubjectException e) {
			assertEquals("Decryption failed: authentication in SIV decryption failed", e.getMessage());
		}
	}
}
