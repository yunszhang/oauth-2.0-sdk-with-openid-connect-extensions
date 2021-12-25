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
import com.nimbusds.openid.connect.sdk.assurance.claims.CountryCode;
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha2CountryCode;
import com.nimbusds.openid.connect.sdk.claims.Address;


public class DocumentIssuerTest extends TestCase {


	public void testEmpty() throws ParseException {
		
		DocumentIssuer documentIssuer = new DocumentIssuer(null, null, null, null);
		
		assertNull(documentIssuer.getName());
		assertNull(documentIssuer.getAddress());
		assertNull(documentIssuer.getCountryCode());
		assertNull(documentIssuer.getJurisdiction());
		
		JSONObject jsonObject = documentIssuer.toJSONObject();
		
		assertTrue(jsonObject.isEmpty());
		
		documentIssuer = DocumentIssuer.parse(jsonObject);
		
		assertNull(documentIssuer.getName());
		assertNull(documentIssuer.getAddress());
		assertNull(documentIssuer.getCountryCode());
		assertNull(documentIssuer.getJurisdiction());
		
		
		assertEquals(documentIssuer, new DocumentIssuer(null, null, null, null));
		assertEquals(documentIssuer.hashCode(), new DocumentIssuer(null, null, null, null).hashCode());
	}
	
	
	public void testFullySet() throws ParseException {
		
		Name name = new Name("Alice");
		
		Address address = new Address();
		address.setStreetAddress("Some street");
		address.setLocality("Some locality");
		address.setPostalCode("1000");
		address.setCountry("Wonderland");
		
		CountryCode countryCode = new ISO3166_1Alpha2CountryCode("BG");
		Jurisdiction jurisdiction = new Jurisdiction("BG-BUL");
		
		DocumentIssuer documentIssuer = new DocumentIssuer(name, address, countryCode, jurisdiction);
		
		assertEquals(name, documentIssuer.getName());
		assertEquals(address, documentIssuer.getAddress());
		assertEquals(countryCode, documentIssuer.getCountryCode());
		assertEquals(jurisdiction, documentIssuer.getJurisdiction());
		
		JSONObject jsonObject = documentIssuer.toJSONObject();
		assertEquals(name.getValue(), jsonObject.get("name"));
		assertEquals(address.getStreetAddress(), jsonObject.get("street_address"));
		assertEquals(address.getLocality(), jsonObject.get("locality"));
		assertEquals(address.getPostalCode(), jsonObject.get("postal_code"));
		assertEquals(address.getCountry(), jsonObject.get("country"));
		assertEquals(countryCode.getValue(), jsonObject.get("country_code"));
		assertEquals(jurisdiction.getValue(), jsonObject.get("jurisdiction"));
		assertEquals(7, jsonObject.size());
		
		documentIssuer = DocumentIssuer.parse(jsonObject);
		assertEquals(name, documentIssuer.getName());
		assertEquals(address, documentIssuer.getAddress());
		assertEquals(countryCode, documentIssuer.getCountryCode());
		assertEquals(jurisdiction, documentIssuer.getJurisdiction());
		
		assertEquals(documentIssuer, new DocumentIssuer(name, address, countryCode, jurisdiction));
		assertEquals(documentIssuer.hashCode(), new DocumentIssuer(name, address, countryCode, jurisdiction).hashCode());
	}
	
	
	public void testInequality() {
		
		DocumentIssuer a = new DocumentIssuer(new Name("Alice"), null, new ISO3166_1Alpha2CountryCode("BG"), null);
		DocumentIssuer b = new DocumentIssuer(new Name("Bob"), null, new ISO3166_1Alpha2CountryCode("US"), null);
		
		assertNotSame(a, b);
		assertNotSame(a.hashCode(), b.hashCode());
	}
	
	
	public void testParseExample() throws ParseException {
		
		String json = "{" +
			"\"name\": \"Stadt Augsburg\"," +
			"\"country\": \"DE\"" +
			"}";
		
		JSONObject jsonObject = JSONObjectUtils.parse(json);
		
		DocumentIssuer documentIssuer = DocumentIssuer.parse(jsonObject);
		
		assertEquals(new Name("Stadt Augsburg"), documentIssuer.getName());
		assertEquals("DE", documentIssuer.getAddress().getCountry());
		
		assertEquals(2, documentIssuer.toJSONObject().size());
	}
}
