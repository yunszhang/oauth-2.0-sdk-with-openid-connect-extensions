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

package com.nimbusds.openid.connect.sdk.assurance.request;


import java.util.Arrays;

import junit.framework.TestCase;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.assurance.IdentityTrustFramework;


public class MinimalVerificationSpecTest extends TestCase {


	// default constructor
	public void testMinimal()
		throws ParseException {
		
		VerificationSpec spec = new MinimalVerificationSpec();
		
		assertEquals("{\"trust_framework\":null}", spec.toJSONObject().toJSONString());
		
		spec = MinimalVerificationSpec.parse(spec.toJSONObject());
		
		assertEquals("{\"trust_framework\":null}", spec.toJSONObject().toJSONString());
	}
	
	
	// IdentityTrustFramework constructor
	public void testWithTrustFramework_set()
		throws ParseException {
		
		VerificationSpec spec = new MinimalVerificationSpec(IdentityTrustFramework.DE_AML);
		
		assertEquals("{\"trust_framework\":{\"value\":\"de_aml\"}}", spec.toJSONObject().toJSONString());
		
		spec = MinimalVerificationSpec.parse(spec.toJSONObject());
		
		assertEquals("{\"trust_framework\":{\"value\":\"de_aml\"}}", spec.toJSONObject().toJSONString());
	}
	
	
	// IdentityTrustFramework constructor
	public void testWithTrustFramework_null()
		throws ParseException {
		
		MinimalVerificationSpec spec = new MinimalVerificationSpec((IdentityTrustFramework) null);
		
		assertEquals("{\"trust_framework\":null}", spec.toJSONObject().toJSONString());
		
		spec = MinimalVerificationSpec.parse(spec.toJSONObject());
		
		assertEquals("{\"trust_framework\":null}", spec.toJSONObject().toJSONString());
	}
	
	
	// List<IdentityTrustFramework> constructor
	public void testWithMultipleTrustFrameworks_set()
		throws ParseException {
		
		VerificationSpec spec = new MinimalVerificationSpec(Arrays.asList(IdentityTrustFramework.DE_AML, IdentityTrustFramework.EIDAS));
		
		assertEquals("{\"trust_framework\":{\"values\":[\"de_aml\",\"eidas\"]}}", spec.toJSONObject().toJSONString());
		
		spec = MinimalVerificationSpec.parse(spec.toJSONObject());
		
		assertEquals("{\"trust_framework\":{\"values\":[\"de_aml\",\"eidas\"]}}", spec.toJSONObject().toJSONString());
	}
	
	
	// List<IdentityTrustFramework> constructor
	public void testWithMultipleTrustFrameworks_null()
		throws ParseException {
		
		MinimalVerificationSpec spec = new MinimalVerificationSpec((IdentityTrustFramework) null);
		
		assertEquals("{\"trust_framework\":null}", spec.toJSONObject().toJSONString());
		
		spec = MinimalVerificationSpec.parse(spec.toJSONObject());
		
		assertEquals("{\"trust_framework\":null}", spec.toJSONObject().toJSONString());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#section-7.6.1
	public void testParseExample()
		throws ParseException {
		
		String json =
			"{" +
			"\"trust_framework\":{\"values\":[\"silver\",\"bronze\"]}" +
			"}";
		
		MinimalVerificationSpec spec = MinimalVerificationSpec.parse(JSONObjectUtils.parse(json));
		
		assertEquals(json, spec.toJSONObject().toJSONString());
	}
	
	
	public void testParse_emptyJSONObject() {
		
		try {
			MinimalVerificationSpec.parse(new JSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing required trust_framework key", e.getMessage());
		}
	}
	
	
	public void testParse_missingTrustFrameworkKey() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("time", null);
		
		try {
			MinimalVerificationSpec.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing required trust_framework key", e.getMessage());
		}
	}
	
	
	public void testParse_emptyTrustFrameworkSpec() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("trust_framework", new JSONObject());
		
		try {
			MinimalVerificationSpec.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid trust_framework spec", e.getMessage());
		}
	}
	
	
	public void testParse_nullTrustFrameworkValue() {
		
		JSONObject jsonObject = new JSONObject();
		JSONObject tfSpec = new JSONObject();
		tfSpec.put("value", null);
		jsonObject.put("trust_framework", tfSpec);
		
		try {
			MinimalVerificationSpec.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid trust_framework spec", e.getMessage());
		}
	}
	
	
	public void testParse_nullTrustFrameworkValues() {
		
		JSONObject jsonObject = new JSONObject();
		JSONObject tfSpec = new JSONObject();
		tfSpec.put("values", null);
		jsonObject.put("trust_framework", tfSpec);
		
		try {
			MinimalVerificationSpec.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid trust_framework spec", e.getMessage());
		}
	}
	
	
	public void testParse_trustFrameworkValueAndValues() {
		
		JSONObject jsonObject = new JSONObject();
		JSONObject tfSpec = new JSONObject();
		tfSpec.put("value", IdentityTrustFramework.EIDAS.getValue());
		JSONArray tfValues = new JSONArray();
		tfValues.add(IdentityTrustFramework.EIDAS.getValue());
		tfValues.add(IdentityTrustFramework.DE_AML.getValue());
		tfSpec.put("values", tfValues);
		jsonObject.put("trust_framework", tfSpec);
		
		try {
			MinimalVerificationSpec.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid trust_framework spec", e.getMessage());
		}
	}
	
	
	public void testParse_trustFramework_value()
		throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		JSONObject tfSpec = new JSONObject();
		tfSpec.put("value", IdentityTrustFramework.DE_AML.getValue());
		jsonObject.put("trust_framework", tfSpec);
		
		MinimalVerificationSpec spec = MinimalVerificationSpec.parse(jsonObject);
		
		assertEquals("{\"trust_framework\":{\"value\":\"de_aml\"}}", spec.toJSONObject().toJSONString());
	}
	
	
	public void testParse_trustFramework_twoValues()
		throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		JSONObject tfSpec = new JSONObject();
		JSONArray tfValues = new JSONArray();
		tfValues.add(IdentityTrustFramework.DE_AML.getValue());
		tfValues.add(IdentityTrustFramework.EIDAS.getValue());
		tfSpec.put("values", tfValues);
		jsonObject.put("trust_framework", tfSpec);
		
		MinimalVerificationSpec spec = MinimalVerificationSpec.parse(jsonObject);
		
		assertEquals("{\"trust_framework\":{\"values\":[\"de_aml\",\"eidas\"]}}", spec.toJSONObject().toJSONString());
	}
	
	
	static class ExtendedSpec extends MinimalVerificationSpec {
		
		public ExtendedSpec(final IdentityTrustFramework framework) {
			super(framework);
		}
		
		public void includeAttachments(final boolean includeAttachments) {
			if (includeAttachments) {
				jsonObject.put("attachments", null);
			} else {
				jsonObject.remove("attachments");
			}
		}
	}
	
	
	public void testExtendWithIncludeAttachmentsSetter() throws ParseException {
		
		ExtendedSpec ext = new ExtendedSpec(IdentityTrustFramework.DE_AML);
		
		assertEquals("{\"trust_framework\":{\"value\":\"de_aml\"}}", ext.toJSONObject().toJSONString());
		
		ext.includeAttachments(true);
		
		JSONObject jsonObject = ext.toJSONObject();
		
		JSONObject tfSpec = JSONObjectUtils.getJSONObject(jsonObject, "trust_framework");
		assertEquals(IdentityTrustFramework.DE_AML.getValue(), tfSpec.get("value"));
		assertEquals(1, tfSpec.size());
		
		assertTrue(jsonObject.containsKey("attachments"));
		assertNull(jsonObject.get("attachments"));
		assertEquals(2, jsonObject.size());
	}
}
