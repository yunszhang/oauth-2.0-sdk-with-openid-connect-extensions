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

package com.nimbusds.openid.connect.sdk.claims;


import java.util.*;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


public class ClaimsSetRequestTest extends TestCase {


	public void testEntryClass_minimal() throws ParseException {
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name");
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("name", jsonObjectEntry.getKey());
		assertNull(jsonObjectEntry.getValue());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}


	public void testEntryClass_minimal_withLangTag() throws ParseException, LangTagException {
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name")
			.withLangTag(LangTag.parse("en-GB"));
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name#en-GB", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertEquals(LangTag.parse("en-GB"), entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("name#en-GB", jsonObjectEntry.getKey());
		assertNull(jsonObjectEntry.getValue());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name#en-GB", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertEquals(LangTag.parse("en-GB"), entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_essential() throws ParseException {
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name")
			.withClaimRequirement(ClaimRequirement.ESSENTIAL);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("name", jsonObjectEntry.getKey());
		JSONObject spec = jsonObjectEntry.getValue();
		assertTrue(JSONObjectUtils.getBoolean(spec, "essential"));
		assertEquals(1, spec.size());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_essential_withValue() throws ParseException {
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name")
			.withClaimRequirement(ClaimRequirement.ESSENTIAL)
			.withValue("Alice Adams");
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertEquals("Alice Adams", entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("name", jsonObjectEntry.getKey());
		JSONObject spec = jsonObjectEntry.getValue();
		assertTrue(JSONObjectUtils.getBoolean(spec, "essential"));
		assertEquals("Alice Adams", spec.get("value"));
		assertEquals(2, spec.size());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertEquals("Alice Adams", entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_essential_withValues() throws ParseException {
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name")
			.withClaimRequirement(ClaimRequirement.ESSENTIAL)
			.withValues(Arrays.asList("Alice Adams", "A. Adams"));
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertEquals(Arrays.asList("Alice Adams", "A. Adams"), entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("name", jsonObjectEntry.getKey());
		JSONObject spec = jsonObjectEntry.getValue();
		assertTrue(JSONObjectUtils.getBoolean(spec, "essential"));
		assertEquals(Arrays.asList("Alice Adams", "A. Adams"), JSONObjectUtils.getStringList(spec, "values"));
		assertEquals(2, spec.size());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertEquals(Arrays.asList("Alice Adams", "A. Adams"), entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_purpose() throws ParseException {
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name")
			.withPurpose("Name verification");
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals("Name verification", entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("name", jsonObjectEntry.getKey());
		JSONObject spec = jsonObjectEntry.getValue();
		assertEquals("Name verification", spec.get("purpose"));
		assertEquals(1, spec.size());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals("Name verification", entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_additionalInfo() throws ParseException {
		
		Map<String,Object> additinalInfo = new HashMap<>();
		additinalInfo.put("info", "custom info");
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name")
			.withAdditionalInformation(additinalInfo);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertEquals(additinalInfo, entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("name", jsonObjectEntry.getKey());
		JSONObject spec = jsonObjectEntry.getValue();
		assertEquals("custom info", spec.get("info"));
		assertEquals(1, spec.size());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertEquals(additinalInfo, entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_fullSpec_withValue() throws ParseException {
		
		Map<String,Object> additinalInfo = new HashMap<>();
		additinalInfo.put("info", "custom info");
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name")
			.withClaimRequirement(ClaimRequirement.ESSENTIAL)
			.withValue("Alice Adams")
			.withPurpose("Name verification")
			.withAdditionalInformation(additinalInfo);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertEquals("Alice Adams", entry.getValue());
		assertNull(entry.getValues());
		assertEquals("Name verification", entry.getPurpose());
		assertEquals(additinalInfo, entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("name", jsonObjectEntry.getKey());
		JSONObject spec = jsonObjectEntry.getValue();
		assertTrue(JSONObjectUtils.getBoolean(spec, "essential"));
		assertEquals("Alice Adams", spec.get("value"));
		assertEquals("Name verification", spec.get("purpose"));
		assertEquals("custom info", spec.get("info"));
		assertEquals(4, spec.size());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertEquals("Alice Adams", entry.getValue());
		assertNull(entry.getValues());
		assertEquals("Name verification", entry.getPurpose());
		assertEquals(additinalInfo, entry.getAdditionalInformation());
	}
	
	
	public void testDefaultConstructor_empty() {
		
		ClaimsSetRequest request = new ClaimsSetRequest();
		assertTrue(request.getEntries().isEmpty());
		assertTrue(request.getClaimNames(true).isEmpty());
		assertTrue(request.getClaimNames(false).isEmpty());
		assertTrue(request.toJSONObject().isEmpty());
		assertEquals("{}", request.toJSONString());
		assertEquals("{}", request.toString());
	}
	
	
	public void testDefaultConstructor_variousOperations() throws ParseException {
		
		ClaimsSetRequest request = new ClaimsSetRequest();
		
		String claimName = "email";
		
		assertEquals(request.getEntries().isEmpty(), request.delete(claimName).getEntries().isEmpty());
		assertEquals(request.getEntries().isEmpty(), request.delete(claimName, null).getEntries().isEmpty());
		
		ClaimsSetRequest afterAdd = request.add(new ClaimsSetRequest.Entry(claimName));
		assertEquals(1, afterAdd.getEntries().size());
		
		ClaimsSetRequest.Entry en = afterAdd.getEntries().iterator().next();
		assertEquals(claimName, en.getClaimName());
		assertEquals(claimName, en.getClaimName(false));
		assertEquals(claimName, en.toJSONObjectEntry().getKey());
		assertNull(en.toJSONObjectEntry().getValue());
		
		en = afterAdd.get(claimName, null);
		assertEquals(claimName, en.getClaimName());
		assertEquals(claimName, en.getClaimName(false));
		assertEquals(claimName, en.toJSONObjectEntry().getKey());
		assertNull(en.toJSONObjectEntry().getValue());
		
		JSONObject jsonObject = afterAdd.toJSONObject();
		assertTrue(jsonObject.containsKey(claimName));
		assertNull(jsonObject.get(claimName));
		assertEquals(1, jsonObject.size());
		
		afterAdd = ClaimsSetRequest.parse(afterAdd.toJSONString());
		
		assertEquals(1, afterAdd.getEntries().size());
		
		en = afterAdd.getEntries().iterator().next();
		assertEquals(claimName, en.getClaimName());
		assertEquals(claimName, en.getClaimName(false));
		assertEquals(claimName, en.toJSONObjectEntry().getKey());
		assertNull(en.toJSONObjectEntry().getValue());
		
		ClaimsSetRequest afterDelete = afterAdd.delete(claimName);
		assertTrue(afterDelete.getEntries().isEmpty());
	}
	
	
	public void testDefaultConstructor_variousOperations_withLangTag() throws ParseException, LangTagException {
		
		ClaimsSetRequest request = new ClaimsSetRequest();
		
		String claimName = "name";
		LangTag langTag = LangTag.parse("bg-BG");
		
		assertEquals(request.getEntries().isEmpty(), request.delete(claimName).getEntries().isEmpty());
		assertEquals(request.getEntries().isEmpty(), request.delete(claimName, langTag).getEntries().isEmpty());
		
		ClaimsSetRequest afterAdd = request.add(new ClaimsSetRequest.Entry(claimName).withLangTag(langTag));
		assertEquals(1, afterAdd.getEntries().size());
		
		ClaimsSetRequest.Entry en = afterAdd.getEntries().iterator().next();
		assertEquals(claimName, en.getClaimName());
		assertEquals(claimName, en.getClaimName(false));
		assertEquals(claimName + "#" + langTag, en.getClaimName(true));
		assertEquals(claimName + "#" + langTag, en.toJSONObjectEntry().getKey());
		assertNull(en.toJSONObjectEntry().getValue());
		
		en = afterAdd.get(claimName, langTag);
		assertEquals(claimName, en.getClaimName());
		assertEquals(claimName, en.getClaimName(false));
		assertEquals(claimName + "#" + langTag, en.getClaimName(true));
		assertEquals(claimName + "#" + langTag, en.toJSONObjectEntry().getKey());
		assertNull(en.toJSONObjectEntry().getValue());
		
		JSONObject jsonObject = afterAdd.toJSONObject();
		assertTrue(jsonObject.containsKey(claimName + "#" + langTag));
		assertNull(jsonObject.get(claimName));
		assertEquals(1, jsonObject.size());
		
		afterAdd = ClaimsSetRequest.parse(afterAdd.toJSONString());
		
		assertEquals(1, afterAdd.getEntries().size());
		
		en = afterAdd.getEntries().iterator().next();
		assertEquals(claimName, en.getClaimName());
		assertEquals(claimName, en.getClaimName(false));
		assertEquals(claimName + "#" + langTag, en.getClaimName(true));
		assertEquals(claimName + "#" + langTag, en.toJSONObjectEntry().getKey());
		assertNull(en.toJSONObjectEntry().getValue());
		
		ClaimsSetRequest afterDelete = afterAdd.delete(claimName);
		assertTrue(afterDelete.getEntries().isEmpty());
	}
	
	
	public void testParse_ignoreVerifiedClaims() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("verified_claims", new JSONObject());
		jsonObject.put("email", null);
		assertEquals(2, jsonObject.size());
		
		ClaimsSetRequest request = ClaimsSetRequest.parse(jsonObject.toJSONString());
		assertEquals(1, request.getEntries().size());
		
		ClaimsSetRequest.Entry en = request.get("email", null);
		assertEquals("email", en.getClaimName());
	}
	
	
	public void testEntriesConstructor_notNull() {
		
		boolean exceptionDetected = false;
		try {
			new ClaimsSetRequest(null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The entries must not be null", e.getMessage());
			exceptionDetected = true;
		}
		assertTrue(exceptionDetected);
	}
	
	
	public void testEntriesConstructor() {
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name");
		Collection<ClaimsSetRequest.Entry> collection = Collections.singletonList(entry);
		
		ClaimsSetRequest request = new ClaimsSetRequest(collection);
		
		assertEquals("name", request.get("name", null).getClaimName());
		assertEquals(1, request.getEntries().size());
	}
	
	
	public void testShorthandAdd() {
		
		ClaimsSetRequest request = new ClaimsSetRequest()
			.add("email");
		
		assertEquals("email", request.get("email", null).getClaimName());
		assertEquals(ClaimRequirement.VOLUNTARY, request.get("email", null).getClaimRequirement());
		assertNull(request.get("email", null).getValue());
		assertNull(request.get("email", null).getValues());
		assertNull(request.get("email", null).getPurpose());
		assertNull(request.get("email", null).getAdditionalInformation());
		
		assertEquals(1, request.getEntries().size());
	}
}
