/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.assurance.request;


import java.util.Collection;
import java.util.Collections;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.assurance.IdentityTrustFramework;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;


public class VerifiedClaimsSetRequestTest extends TestCase {


	public void testDefaultConstructor() 
		throws ParseException {
		
		VerifiedClaimsSetRequest request = new VerifiedClaimsSetRequest();
		assertTrue(request.getEntries().isEmpty());
		assertEquals("{\"trust_framework\":null}", request.getVerification().toJSONObject().toJSONString());
		
		request = request.add(new ClaimsSetRequest.Entry("name"));
		ClaimsSetRequest.Entry en = request.get("name", null);
		assertEquals("name", en.getClaimName());
		
		VerificationSpec verification = new MinimalVerificationSpec(IdentityTrustFramework.EIDAS);
		
		request = request.withVerification(verification);
		assertEquals(verification, request.getVerification());
		
		JSONObject jsonObject = request.toJSONObject();
		assertEquals(2, jsonObject.size());
		
		JSONObject verificationJSONObject = JSONObjectUtils.getJSONObject(jsonObject, "verification");
		assertEquals(verification.toJSONObject(), verificationJSONObject);
		
		JSONObject claimsJSONObject = JSONObjectUtils.getJSONObject(jsonObject, "claims");
		assertTrue(claimsJSONObject.containsKey("name"));
		assertNull(claimsJSONObject.get("name"));
		assertEquals(1, claimsJSONObject.size());
		
		VerifiedClaimsSetRequest parsed = VerifiedClaimsSetRequest.parse(jsonObject.toJSONString());
		assertEquals(jsonObject, parsed.toJSONObject());
	}


	public void testToJSONObject_illegalStateExceptionOnMissingClaims() {
		
		try {
			new VerifiedClaimsSetRequest().toJSONObject();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Empty verified claims object", e.getMessage());
		}
	}
	
	
	public void testParamConstructor_entriesNotNull() {
		
		boolean exceptionDetected = false;
		try {
			new VerifiedClaimsSetRequest(null, new MinimalVerificationSpec());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The entries must not be null", e.getMessage());
			exceptionDetected = true;
		}
		assertTrue(exceptionDetected);
	}
	
	
	public void testParamConstructor_verificationNotNull() {
		
		boolean exceptionDetected = false;
		try {
			new VerifiedClaimsSetRequest(Collections.singletonList(new ClaimsSetRequest.Entry("name")), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The verification element must not be null", e.getMessage());
			exceptionDetected = true;
		}
		assertTrue(exceptionDetected);
	}
	
	
	public void testParamConstructor() 
		throws ParseException {
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name");
		Collection<ClaimsSetRequest.Entry> collection = Collections.singletonList(entry);
		
		VerificationSpec verificationRequest = new MinimalVerificationSpec();
		
		VerifiedClaimsSetRequest request = new VerifiedClaimsSetRequest(collection, verificationRequest);
		
		assertEquals("name", request.get("name", null).getClaimName());
		assertEquals(1, request.getEntries().size());
		
		assertEquals(verificationRequest, request.getVerification());
		
		JSONObject jsonObject = request.toJSONObject();
		assertEquals(2, jsonObject.size());
		
		JSONObject claimsJSONObject = JSONObjectUtils.getJSONObject(jsonObject, "claims");
		assertTrue(claimsJSONObject.containsKey("name"));
		assertNull(claimsJSONObject.get("name"));
		assertEquals(1, claimsJSONObject.size());
		
		VerifiedClaimsSetRequest parsed = VerifiedClaimsSetRequest.parse(jsonObject.toJSONString());
		assertEquals(request.toJSONObject(), parsed.toJSONObject());
	}
	
	
	public void testDelete_langTagArg() {
		
		VerifiedClaimsSetRequest request = new VerifiedClaimsSetRequest()
			.add(new ClaimsSetRequest.Entry("email"));
		
		assertEquals(1, request.getEntries().size());
		
		request = request.delete("email", null);
		
		assertTrue(request.getEntries().isEmpty());
	}
	
	
	public void testDelete_forAllLangTags() {
		
		VerifiedClaimsSetRequest request = new VerifiedClaimsSetRequest()
			.add(new ClaimsSetRequest.Entry("email"));
		
		assertEquals(1, request.getEntries().size());
		
		request = request.delete("email");
		
		assertTrue(request.getEntries().isEmpty());
	}
	
	
	public void testShorthandAdd() {
		
		VerifiedClaimsSetRequest request = new VerifiedClaimsSetRequest()
			.add("email");
		
		assertEquals("email", request.get("email", null).getClaimName());
		assertEquals(ClaimRequirement.VOLUNTARY, request.get("email", null).getClaimRequirement());
		assertNull(request.get("email", null).getRawValue());
		assertNull(request.get("email", null).getPurpose());
		assertNull(request.get("email", null).getAdditionalInformation());
		
		assertEquals(1, request.getEntries().size());
	}
	
	
	public void testParse_rejectInvalidVerificationObject() {
		
		String json =
			"{" +
			"   \"verification\": {" +
			"      \"trust_framework\": {}" +
			"   }," +
			"   \"claims\": {\"email\": null}" +
			"}";
		
		try {
			VerifiedClaimsSetRequest.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid trust_framework spec", e.getMessage());
			assertNull(e.getErrorObject());
		}
	}
	
	
	public void testParse_rejectEmptyClaimsObject() {
		
		String json =
			"{" +
			"   \"verification\": {" +
			"      \"trust_framework\": null" +
			"   }," +
			"   \"claims\":{}" +
			"}";
		
		try {
			VerifiedClaimsSetRequest.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Empty verified claims object", e.getMessage());
			assertNull(e.getErrorObject());
		}
	}
	
	
	public void testParseExample() throws ParseException {
		
		String json =
			"{" +
			"   \"verification\": {" +
			"      \"trust_framework\": null" +
			"   }," +
			"   \"claims\":{" +
			"      \"given_name\":null," +
			"      \"family_name\":null," +
			"      \"birthdate\":null" +
			"   }" +
			"}";
		
		VerifiedClaimsSetRequest request = VerifiedClaimsSetRequest.parse(json);
		
		assertTrue(request.getVerification().toJSONObject().containsKey("trust_framework"));
		assertNull(request.getVerification().toJSONObject().get("trust_framework"));
		assertEquals(1, request.getVerification().toJSONObject().size());
		
		assertNotNull(request.get("given_name", null));
		assertNotNull(request.get("family_name", null));
		assertNotNull(request.get("birthdate", null));
		assertEquals(3, request.getEntries().size());
	}
}
