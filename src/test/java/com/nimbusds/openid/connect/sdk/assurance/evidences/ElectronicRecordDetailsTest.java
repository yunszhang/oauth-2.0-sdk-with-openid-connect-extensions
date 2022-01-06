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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.DateWithTimeZoneOffset;
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha3CountryCode;
import com.nimbusds.openid.connect.sdk.claims.Address;


public class ElectronicRecordDetailsTest extends TestCase {
	
	
	public void testMinimal()
		throws ParseException {
		
		ElectronicRecordType type = ElectronicRecordType.POPULATION_REGISTER;
		ElectronicRecordDetails details = new ElectronicRecordDetails(type, null, null, null, null);
		assertEquals(type, details.getType());
		assertNull(details.getPersonalNumber());
		assertNull(details.getCreatedAt());
		assertNull(details.getDateOfExpiry());
		assertNull(details.getSource());
		
		JSONObject jsonObject = details.toJSONObject();
		assertEquals(type.getValue(), jsonObject.get("type"));
		assertEquals(1, jsonObject.size());
		
		details = ElectronicRecordDetails.parse(jsonObject);
		assertEquals(type, details.getType());
		assertNull(details.getPersonalNumber());
		assertNull(details.getCreatedAt());
		assertNull(details.getDateOfExpiry());
		assertNull(details.getSource());
		
		assertEquals("Equality", details, ElectronicRecordDetails.parse(jsonObject));
		assertEquals("Hash code", details.hashCode(), ElectronicRecordDetails.parse(jsonObject).hashCode());
	}


	public void testFullySet()
		throws ParseException {
	
		ElectronicRecordType type = ElectronicRecordType.POPULATION_REGISTER;
		PersonalNumber personalNumber = new PersonalNumber("4901224131");
		DateWithTimeZoneOffset createdAt = DateWithTimeZoneOffset.parseISO8601String("1979-01-22T12:15Z");
		SimpleDate dateOfExpiry = new SimpleDate(2099, 12, 31);
		Address address = new Address();
		address.setCountry("Sverige");
		ElectronicRecordSource source = new ElectronicRecordSource(
			new Name("Skatteverket"),
			address,
			new ISO3166_1Alpha3CountryCode("SWE"),
			null
		);
		ElectronicRecordDetails details = new ElectronicRecordDetails(
			type,
			personalNumber,
			createdAt,
			dateOfExpiry,
			source
		);
		
		assertEquals(type, details.getType());
		assertEquals(personalNumber, details.getPersonalNumber());
		assertEquals(createdAt, details.getCreatedAt());
		assertEquals(dateOfExpiry, details.getDateOfExpiry());
		assertEquals(source, details.getSource());
		
		JSONObject jsonObject = details.toJSONObject();
		assertEquals(type.getValue(), jsonObject.get("type"));
		assertEquals(personalNumber.getValue(), jsonObject.get("personal_number"));
		assertEquals(createdAt.toISO8601String(), jsonObject.get("created_at"));
		assertEquals(dateOfExpiry.toISO8601String(), jsonObject.get("date_of_expiry"));
		JSONObject sourceObject = JSONObjectUtils.getJSONObject(jsonObject, "source");
		assertEquals(source.getName().getValue(), sourceObject.get("name"));
		assertEquals(source.getAddress().getCountry(), sourceObject.get("country"));
		assertEquals(source.getCountryCode().getValue(), sourceObject.get("country_code"));
		assertEquals(3, sourceObject.size());
		assertEquals(5, jsonObject.size());
		
		details = ElectronicRecordDetails.parse(jsonObject);
		
		assertEquals(type, details.getType());
		assertEquals(personalNumber, details.getPersonalNumber());
		assertEquals(createdAt, details.getCreatedAt());
		assertEquals(dateOfExpiry, details.getDateOfExpiry());
		assertEquals(source, details.getSource());
		
		assertEquals(details, ElectronicRecordDetails.parse(jsonObject));
		assertEquals(details.hashCode(), ElectronicRecordDetails.parse(jsonObject).hashCode());
	}
	
	
	public void testRequireType() {
		
		try {
			new ElectronicRecordDetails(null, null, null, null, null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testParseExample()
		throws ParseException {
		
		String json = "{" +
			"  \"type\": \"population_register\"," +
			"  \"source\": {" +
			"      \"name\": \"Skatteverket\"," +
			"      \"country\": \"Sverige\"," +
			"      \"country_code\": \"SWE\"" +
			"  }," +
			"  \"personal_number\": \"4901224131\"," +
			"  \"created_at\": \"1979-01-22T12:15Z\"" +
			"}";
		
		ElectronicRecordDetails details = ElectronicRecordDetails.parse(JSONObjectUtils.parse(json));
		
		assertEquals(ElectronicRecordType.POPULATION_REGISTER, details.getType());
		assertEquals(new PersonalNumber("4901224131"), details.getPersonalNumber());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("1979-01-22T12:15Z"), details.getCreatedAt());
		assertEquals(new Name("Skatteverket"), details.getSource().getName());
		assertEquals("Sverige", details.getSource().getAddress().getCountry());
		assertEquals(new ISO3166_1Alpha3CountryCode("SWE"), details.getSource().getCountryCode());
	}
	
	
	public void testParseEmpty() {
		
		try {
			ElectronicRecordDetails.parse(new JSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key type", e.getMessage());
		}
	}
}
