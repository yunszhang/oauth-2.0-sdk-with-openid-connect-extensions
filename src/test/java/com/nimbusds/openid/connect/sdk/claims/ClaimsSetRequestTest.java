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
import org.opensaml.xmlsec.signature.J;

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
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertNull(entry.getValuesAsRawList());
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
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertNull(entry.getValuesAsRawList());
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
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertNull(entry.getValuesAsRawList());
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
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertNull(entry.getValuesAsRawList());
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
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertNull(entry.getValuesAsRawList());
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
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertNull(entry.getValuesAsRawList());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_essential_withValueAsString() throws ParseException {
		
		String name = "Alice Adams";
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name")
			.withClaimRequirement(ClaimRequirement.ESSENTIAL)
			.withValue(name);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertEquals(name, entry.getValueAsString());
		assertEquals(name, entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertEquals(name, entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertNull(entry.getValuesAsRawList());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("name", jsonObjectEntry.getKey());
		JSONObject spec = jsonObjectEntry.getValue();
		assertTrue(JSONObjectUtils.getBoolean(spec, "essential"));
		assertEquals(name, spec.get("value"));
		assertEquals(2, spec.size());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertEquals(name, entry.getValueAsString());
		assertEquals(name, entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertEquals(name, entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertNull(entry.getValuesAsRawList());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_essential_withValueAsNumber() throws ParseException {
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("age")
			.withClaimRequirement(ClaimRequirement.ESSENTIAL)
			.withValue(18);
		
		assertEquals("age", entry.getClaimName());
		assertEquals("age", entry.getClaimName(false));
		assertEquals("age", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertEquals(18, entry.getValueAsNumber().intValue());
		assertNull(entry.getValueAsJSONObject());
		assertEquals(18, entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertNull(entry.getValuesAsRawList());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("age", jsonObjectEntry.getKey());
		JSONObject spec = jsonObjectEntry.getValue();
		assertTrue(JSONObjectUtils.getBoolean(spec, "essential"));
		assertEquals(18, spec.get("value"));
		assertEquals(2, spec.size());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("age", entry.getClaimName());
		assertEquals("age", entry.getClaimName(false));
		assertEquals("age", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertEquals(18, entry.getValueAsNumber().intValue());
		assertNull(entry.getValueAsJSONObject());
		assertEquals(18, entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertNull(entry.getValuesAsRawList());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_withValueAsJSONObject() throws ParseException {
		
		JSONObject tx = new JSONObject();
		tx.put("data", "abc");
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("transaction").withValue(tx);
		
		assertEquals("transaction", entry.getClaimName());
		assertEquals("transaction", entry.getClaimName(false));
		assertEquals("transaction", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertEquals(tx, entry.getValueAsJSONObject());
		assertEquals(tx, entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertNull(entry.getValuesAsRawList());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("transaction", jsonObjectEntry.getKey());
		JSONObject expectedValue = new JSONObject();
		expectedValue.put("value", tx);
		assertEquals(expectedValue, jsonObjectEntry.getValue());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("transaction", entry.getClaimName());
		assertEquals("transaction", entry.getClaimName(false));
		assertEquals("transaction", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertEquals(tx, entry.getValueAsJSONObject());
		assertEquals(tx, entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertNull(entry.getValuesAsRawList());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_essential_withRawValue() throws ParseException {
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("pi")
			.withClaimRequirement(ClaimRequirement.ESSENTIAL)
			.withValue((Object) 3.14);
		
		assertEquals("pi", entry.getClaimName());
		assertEquals("pi", entry.getClaimName(false));
		assertEquals("pi", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertNull(entry.getValuesAsRawList());
		assertEquals(3.14, entry.getValueAsNumber().doubleValue());
		assertNull(entry.getValueAsJSONObject());
		assertEquals(3.14, entry.getRawValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("pi", jsonObjectEntry.getKey());
		JSONObject spec = jsonObjectEntry.getValue();
		assertTrue(JSONObjectUtils.getBoolean(spec, "essential"));
		assertEquals(3.14, spec.get("value"));
		assertEquals(2, spec.size());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertEquals(3.14, entry.getValueAsNumber().doubleValue());
		assertNull(entry.getValueAsJSONObject());
		assertEquals(3.14, entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertNull(entry.getValuesAsRawList());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_essential_withValuesAsStrings() throws ParseException {
		
		List<?> values = Arrays.asList("Alice Adams", "A. Adams");
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name")
			.withClaimRequirement(ClaimRequirement.ESSENTIAL)
			.withValues(values);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertEquals(values, entry.getValuesAsListOfStrings());
		assertEquals(values, entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertEquals(values, entry.getValuesAsRawList());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("name", jsonObjectEntry.getKey());
		JSONObject spec = jsonObjectEntry.getValue();
		assertTrue(JSONObjectUtils.getBoolean(spec, "essential"));
		assertEquals(values, JSONObjectUtils.getStringList(spec, "values"));
		assertEquals(2, spec.size());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertEquals(values, entry.getValuesAsListOfStrings());
		assertEquals(values, entry.getValues());
		assertNull(entry.getValuesAsListOfJSONObjects());
		assertEquals(values, entry.getValuesAsRawList());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_essential_withValuesEmpty() throws ParseException {
		
		List<?> values = Collections.emptyList();
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name")
			.withClaimRequirement(ClaimRequirement.ESSENTIAL)
			.withValues(values);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertTrue(entry.getValuesAsListOfStrings().isEmpty());
		assertTrue(entry.getValues().isEmpty());
		assertTrue(entry.getValuesAsListOfJSONObjects().isEmpty());
		assertTrue(entry.getValuesAsRawList().isEmpty());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("name", jsonObjectEntry.getKey());
		JSONObject spec = jsonObjectEntry.getValue();
		assertTrue(JSONObjectUtils.getBoolean(spec, "essential"));
		assertTrue(JSONObjectUtils.getList(spec, "values").isEmpty());
		assertEquals(2, spec.size());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertTrue(entry.getValuesAsListOfStrings().isEmpty());
		assertTrue(entry.getValues().isEmpty());
		assertTrue(entry.getValuesAsListOfJSONObjects().isEmpty());
		assertTrue(entry.getValuesAsRawList().isEmpty());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_essential_withValuesAsJSONObjects() throws ParseException {
		
		JSONObject o1 = new JSONObject();
		o1.put("k1", "v1");
		JSONObject o2 = new JSONObject();
		o2.put("k2", "v2");
		List<?> values = Arrays.asList(o1, o2);
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("some-claim")
			.withClaimRequirement(ClaimRequirement.ESSENTIAL)
			.withValues(values);
		
		assertEquals("some-claim", entry.getClaimName());
		assertEquals("some-claim", entry.getClaimName(false));
		assertEquals("some-claim", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertEquals(values, entry.getValuesAsListOfJSONObjects());
		assertEquals(values, entry.getValuesAsRawList());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("some-claim", jsonObjectEntry.getKey());
		JSONObject spec = jsonObjectEntry.getValue();
		assertTrue(JSONObjectUtils.getBoolean(spec, "essential"));
		assertEquals(values, JSONObjectUtils.getList(spec, "values"));
		assertEquals(2, spec.size());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("some-claim", entry.getClaimName());
		assertEquals("some-claim", entry.getClaimName(false));
		assertEquals("some-claim", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertNull(entry.getValuesAsListOfStrings());
		assertNull(entry.getValues());
		assertEquals(values, entry.getValuesAsListOfJSONObjects());
		assertEquals(values, entry.getValuesAsRawList());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_purpose() throws ParseException {
		
		String purpose = "Name verification";
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name")
			.withPurpose(purpose);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertNull(entry.getValues());
		assertEquals(purpose, entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
		assertEquals("name", jsonObjectEntry.getKey());
		JSONObject spec = jsonObjectEntry.getValue();
		assertEquals(purpose, spec.get("purpose"));
		assertEquals(1, spec.size());
		
		entry = ClaimsSetRequest.Entry.parse(jsonObjectEntry);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertNull(entry.getValues());
		assertEquals(purpose, entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_additionalInfo() throws ParseException {
		
		Map<String,Object> additionalInfo = new HashMap<>();
		additionalInfo.put("info", "custom info");
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name")
			.withAdditionalInformation(additionalInfo);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertEquals(additionalInfo, entry.getAdditionalInformation());
		
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
		assertNull(entry.getValueAsString());
		assertNull(entry.getValue());
		assertNull(entry.getValueAsNumber());
		assertNull(entry.getValueAsJSONObject());
		assertNull(entry.getRawValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertEquals(additionalInfo, entry.getAdditionalInformation());
	}
	
	
	public void testEntryClass_fullSpec_withValue() throws ParseException {
		
		Map<String,Object> additionalInfo = new HashMap<>();
		additionalInfo.put("info", "custom info");
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name")
			.withClaimRequirement(ClaimRequirement.ESSENTIAL)
			.withValue("Alice Adams")
			.withPurpose("Name verification")
			.withAdditionalInformation(additionalInfo);
		
		assertEquals("name", entry.getClaimName());
		assertEquals("name", entry.getClaimName(false));
		assertEquals("name", entry.getClaimName(true));
		
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertEquals("Alice Adams", entry.getValueAsString());
		assertEquals("Alice Adams", entry.getValue());
		assertNull(entry.getValues());
		assertEquals("Name verification", entry.getPurpose());
		assertEquals(additionalInfo, entry.getAdditionalInformation());
		
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
		assertEquals("Alice Adams", entry.getValueAsString());
		assertEquals("Alice Adams", entry.getValue());
		assertNull(entry.getValues());
		assertEquals("Name verification", entry.getPurpose());
		assertEquals(additionalInfo, entry.getAdditionalInformation());
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
