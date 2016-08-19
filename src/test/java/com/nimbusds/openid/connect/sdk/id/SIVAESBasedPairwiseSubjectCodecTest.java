package com.nimbusds.openid.connect.sdk.id;


import java.net.URI;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.oauth2.sdk.id.Subject;
import junit.framework.TestCase;


public class SIVAESBasedPairwiseSubjectCodecTest extends TestCase {
	
	
	public void testWith256BitKey()
		throws Exception {
		
		byte[] keyBytes = new byte[ByteUtils.byteLength(256)];
		new SecureRandom().nextBytes(keyBytes);
		
		SIVAESBasedPairwiseSubjectCodec codec = new SIVAESBasedPairwiseSubjectCodec(new SecretKeySpec(keyBytes, "AES"));
		
		assertTrue(Arrays.equals(keyBytes, codec.getSecretKey().getEncoded()));
		
		SectorID sectorID = new SectorID(URI.create("https://example.com"));
		Subject subject = new Subject("alice");
		
		Subject pairwiseSubject = codec.encode(sectorID, subject);
		
		System.out.println("Pairwise subject: " + pairwiseSubject);
		
		// Repeat
		for (int i=0; i < 1000; i++) {
			assertEquals(pairwiseSubject, codec.encode(sectorID, subject));
		}
		
		assertEquals(subject, codec.decode(pairwiseSubject).getRight());
		assertEquals(sectorID, codec.decode(pairwiseSubject).getLeft());
	}
	
	
	public void testWith384BitKey()
		throws Exception {
		
		byte[] keyBytes = new byte[ByteUtils.byteLength(384)];
		new SecureRandom().nextBytes(keyBytes);
		
		SIVAESBasedPairwiseSubjectCodec codec = new SIVAESBasedPairwiseSubjectCodec(new SecretKeySpec(keyBytes, "AES"));
		
		assertTrue(Arrays.equals(keyBytes, codec.getSecretKey().getEncoded()));
		
		SectorID sectorID = new SectorID(URI.create("https://example.com"));
		Subject subject = new Subject("alice");
		
		Subject pairwiseSubject = codec.encode(sectorID, subject);
		
		System.out.println("Pairwise subject: " + pairwiseSubject);
		
		// Repeat
		for (int i=0; i < 1000; i++) {
			assertEquals(pairwiseSubject, codec.encode(sectorID, subject));
		}
		
		assertEquals(subject, codec.decode(pairwiseSubject).getRight());
		assertEquals(sectorID, codec.decode(pairwiseSubject).getLeft());
	}
	
	
	public void testWith512BitKey()
		throws Exception {
		
		byte[] keyBytes = new byte[ByteUtils.byteLength(512)];
		new SecureRandom().nextBytes(keyBytes);
		
		SIVAESBasedPairwiseSubjectCodec codec = new SIVAESBasedPairwiseSubjectCodec(new SecretKeySpec(keyBytes, "AES"));
		
		assertTrue(Arrays.equals(keyBytes, codec.getSecretKey().getEncoded()));
		
		SectorID sectorID = new SectorID(URI.create("https://example.com"));
		Subject subject = new Subject("alice");
		
		Subject pairwiseSubject = codec.encode(sectorID, subject);
		
		System.out.println("Pairwise subject: " + pairwiseSubject);
		
		// Repeat
		for (int i=0; i < 1000; i++) {
			assertEquals(pairwiseSubject, codec.encode(sectorID, subject));
		}
		
		assertEquals(subject, codec.decode(pairwiseSubject).getRight());
		assertEquals(sectorID, codec.decode(pairwiseSubject).getLeft());
	}
	
	
	public void testUnsupportedKeyLength()
		throws Exception {
		
		byte[] keyBytes = new byte[ByteUtils.byteLength(128)];
		new SecureRandom().nextBytes(keyBytes);
		
		try {
			new SIVAESBasedPairwiseSubjectCodec(new SecretKeySpec(keyBytes, "AES"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The SIV AES secret key length must be 256, 384 or 512 bits", e.getMessage());
		}
	}
	
	
	public void testDecryptFail()
		throws Exception {
		
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
