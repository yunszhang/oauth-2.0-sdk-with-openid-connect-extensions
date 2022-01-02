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


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.ContentTest.SAMPLE_ID_CARD_JPEG;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.ParseException;


public class DigestTest extends TestCase {


	public void testGetSetAndParse()
		throws ParseException {
	
		HashAlgorithm alg = HashAlgorithm.SHA_256;
		Base64 value = new Base64("i3O7U79LiyKmmesIgULKT2Q8LAxNO0CpwJVcbepaYf8");
		
		Digest digest = new Digest(alg, value);
		assertEquals(alg, digest.getHashAlgorithm());
		assertEquals(value, digest.getValue());
		
		JSONObject jsonObject = digest.toJSONObject();
		assertEquals(alg.getValue(), jsonObject.get("alg"));
		assertEquals(value.toString(), jsonObject.get("value"));
		assertEquals(2, jsonObject.size());
		
		digest = Digest.parse(jsonObject);
		assertEquals(alg, digest.getHashAlgorithm());
		assertEquals(value, digest.getValue());
	}
	
	
	public void testEqualityAndHashCode() {
		
		HashAlgorithm alg = HashAlgorithm.SHA_256;
		Base64 value = new Base64("i3O7U79LiyKmmesIgULKT2Q8LAxNO0CpwJVcbepaYf8");
		Digest a = new Digest(alg, value);
		Digest b = new Digest(alg, value);
		
		assertEquals(a, b);
		assertEquals(a.hashCode(), b.hashCode());
	}
	
	
	public void testInequalityAndHashCode_valuesDiffer() {
		
		Digest a = new Digest(HashAlgorithm.SHA_256, new Base64("i3O7U79LiyKmmesIgULKT2Q8LAxNO0CpwJVcbepaYf8"));
		Digest b = new Digest(HashAlgorithm.SHA_256, new Base64("nVW19w6EVNWNQ8fmRCxrxqw4xLUs+T8eI0tpjZo820Bc"));
		
		assertNotSame(a, b);
		assertNotSame(a.hashCode(), b.hashCode());
	}
	
	
	public void testInequalityAndHashCode_algorithmsDiffer() {
		
		Digest a = new Digest(HashAlgorithm.SHA_256, new Base64("i3O7U79LiyKmmesIgULKT2Q8LAxNO0CpwJVcbepaYf8"));
		Digest b = new Digest(HashAlgorithm.SHA_384, new Base64("i3O7U79LiyKmmesIgULKT2Q8LAxNO0CpwJVcbepaYf8"));
		
		assertNotSame(a, b);
		assertNotSame(a.hashCode(), b.hashCode());
	}
	
	
	public void testComputeAndMatch()
		throws NoSuchAlgorithmException {
		
		for (HashAlgorithm alg: Arrays.asList(HashAlgorithm.SHA_256, HashAlgorithm.SHA_384, HashAlgorithm.SHA_512)) {
			
			Digest digest = Digest.compute(alg, SAMPLE_ID_CARD_JPEG);
			
			assertEquals(alg, digest.getHashAlgorithm());
			
			byte[] expectedHashBytes = MessageDigest.getInstance(alg.getValue().toUpperCase()).digest(SAMPLE_ID_CARD_JPEG.decode());
			Base64 expectedHashB64 = Base64.encode(expectedHashBytes);
			
			assertEquals(expectedHashB64, digest.getValue());
			
			assertTrue(digest.matches(SAMPLE_ID_CARD_JPEG));
			assertFalse(digest.matches(new Base64("abc")));
		}
	}
	
	
	public void testCompute_unsupportedAlg() {
		
		try {
			Digest.compute(new HashAlgorithm("no-such-alg"), SAMPLE_ID_CARD_JPEG);
			fail();
		} catch (NoSuchAlgorithmException e) {
			assertEquals("NO-SUCH-ALG MessageDigest not available", e.getMessage());
		}
	}
	
	
	public void testParse_missingAlg() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("value", "i3O7U79LiyKmmesIgULKT2Q8LAxNO0CpwJVcbepaYf8");
		
		try {
			Digest.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key alg", e.getMessage());
		}
	}
	
	
	public void testParse_missingValue() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("alg", "sha-256");
		
		try {
			Digest.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key value", e.getMessage());
		}
	}
}
