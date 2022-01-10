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
import java.util.Arrays;
import java.util.Random;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;

import junit.framework.TestCase;

import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.oauth2.sdk.id.Subject;


public class SIVAESBasedPairwiseSubjectCodecTest extends TestCase {
	
	
	public void testWithoutPadding()
		throws Exception {
		
		for (int keyBitSize: Arrays.asList(256, 384, 512)) {
			
			byte[] keyBytes = new byte[ByteUtils.byteLength(keyBitSize)];
			new SecureRandom().nextBytes(keyBytes);
			
			SIVAESBasedPairwiseSubjectCodec codec = new SIVAESBasedPairwiseSubjectCodec(new SecretKeySpec(keyBytes, "AES"));
			assertArrayEquals(keyBytes, codec.getSecretKey().getEncoded());
			assertEquals(-1, codec.getPadSubjectToLength());
			
			SectorID sectorID = new SectorID(URI.create("https://example.com"));
			Subject subject = new Subject("alice");
			
			Subject pairwiseSubject = codec.encode(sectorID, subject);
			
//			System.out.println("Pairwise subject (" + keyBitSize + " bit key): " + pairwiseSubject);
			
			// Repeat
			for (int i = 0; i < 1000; i++) {
				assertEquals(pairwiseSubject, codec.encode(sectorID, subject));
			}
			
			assertEquals(sectorID, codec.decode(pairwiseSubject).getKey());
			assertEquals(subject, codec.decode(pairwiseSubject).getValue());
		}
	}
	
	
	public void testWithPadding()
		throws Exception {
		
		for (int keyBitSize: Arrays.asList(256, 384, 512)) {
			
			byte[] keyBytes = new byte[ByteUtils.byteLength(keyBitSize)];
			new SecureRandom().nextBytes(keyBytes);
			
			int padToLength = 8;
			
			SIVAESBasedPairwiseSubjectCodec codec = new SIVAESBasedPairwiseSubjectCodec(new SecretKeySpec(keyBytes, "AES"), padToLength);
			assertArrayEquals(keyBytes, codec.getSecretKey().getEncoded());
			assertEquals(padToLength, codec.getPadSubjectToLength());
			
			SectorID sectorID = new SectorID(URI.create("https://example.com"));
			
			int  pairwiseSubjectLength = -1;
			
			// Vary subject len from 1 to 8 chars
			for (Subject subject: Arrays.asList(
				new Subject("1"),
				new Subject("12"),
				new Subject("123"),
				new Subject("1234"),
				new Subject("12345"),
				new Subject("123456"),
				new Subject("1234567"),
				new Subject("12345678"))) {
				
				Subject pairwiseSubject = codec.encode(sectorID, subject);
				
				if (pairwiseSubjectLength == -1) {
					pairwiseSubjectLength = pairwiseSubject.getValue().length();
				} else if (pairwiseSubjectLength != pairwiseSubject.getValue().length()) {
					fail("Unexpected change in length");
				}
				
//				System.out.println("Pairwise subject (" + keyBitSize + " bit key): " + pairwiseSubject);
				
				assertEquals(sectorID, codec.decode(pairwiseSubject).getKey());
				assertEquals(subject, codec.decode(pairwiseSubject).getValue());
			}
			
			// Vary subject len from 9 to 11 chars
			for (Subject subject: Arrays.asList(
				new Subject("123456789"),
				new Subject("1234567890"),
				new Subject("12345678901"))) {
				
				Subject pairwiseSubject = codec.encode(sectorID, subject);
				
				assertTrue(pairwiseSubjectLength < pairwiseSubject.getValue().length());
				
				pairwiseSubjectLength = pairwiseSubject.getValue().length();
				
//				System.out.println("Pairwise subject (" + keyBitSize + " bit key): " + pairwiseSubject);
				
				assertEquals(sectorID, codec.decode(pairwiseSubject).getKey());
				assertEquals(subject, codec.decode(pairwiseSubject).getValue());
			}
		}
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
	
	
	public void testWithEscapedSeparatorChars()
		throws Exception {
		
		byte[] keyBytes = new byte[ByteUtils.byteLength(256)];
		new SecureRandom().nextBytes(keyBytes);
		
		SIVAESBasedPairwiseSubjectCodec codec = new SIVAESBasedPairwiseSubjectCodec(new SecretKeySpec(keyBytes, "AES"));
		
		SectorID sectorID = new SectorID(URI.create("https://example.com"));
		Subject subject = new Subject("a|b|c");
		
		Subject pairwiseSubject = codec.encode(sectorID, subject);
		
		assertEquals(sectorID, codec.decode(pairwiseSubject).getKey());
		assertEquals(subject, codec.decode(pairwiseSubject).getValue());
	}
	
	
	public void testRandomLocalSubjectLength() throws InvalidPairwiseSubjectException {
		
		byte[] keyBytes = new byte[ByteUtils.byteLength(256)];
		new SecureRandom().nextBytes(keyBytes);
		
		SIVAESBasedPairwiseSubjectCodec codec = new SIVAESBasedPairwiseSubjectCodec(new SecretKeySpec(keyBytes, "AES"));
	
		for (int i=0; i < 100; i++) {
			
			int subByteLen = new Random().nextInt(11) + 1; // 1 .. 12
			Subject localSubject = new Subject(subByteLen);
			
			Subject pairWiseSubject = codec.encode(new SectorID("example.com"), localSubject);
//			System.out.println(pairWiseSubject);
			assertEquals(localSubject, codec.decode(pairWiseSubject).getValue());
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
