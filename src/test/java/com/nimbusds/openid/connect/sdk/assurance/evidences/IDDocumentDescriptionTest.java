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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;
import com.nimbusds.openid.connect.sdk.assurance.claims.CountryCode;
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha2CountryCode;


public class IDDocumentDescriptionTest extends TestCase {
	
	
	public void testMinimal() throws ParseException {
		
		IDDocumentDescription idDocumentDescription = new IDDocumentDescription(IDDocumentType.IDCARD, null, null, null, null, null);
		
		assertEquals(IDDocumentType.IDCARD, idDocumentDescription.getType());
		assertNull(idDocumentDescription.getNumber());
		assertNull(idDocumentDescription.getIssuerName());
		assertNull(idDocumentDescription.getIssuerCountry());
		assertNull(idDocumentDescription.getDateOfIssuance());
		assertNull(idDocumentDescription.getDateOfExpiry());
		
		JSONObject jsonObject = idDocumentDescription.toJSONObject();
		assertEquals(IDDocumentType.IDCARD.getValue(), jsonObject.get("type"));
		assertEquals(1, jsonObject.size());
		
		idDocumentDescription = IDDocumentDescription.parse(jsonObject);
		
		assertEquals(IDDocumentType.IDCARD, idDocumentDescription.getType());
		assertNull(idDocumentDescription.getNumber());
		assertNull(idDocumentDescription.getIssuerName());
		assertNull(idDocumentDescription.getIssuerCountry());
		assertNull(idDocumentDescription.getDateOfIssuance());
		assertNull(idDocumentDescription.getDateOfExpiry());
	}
	
	
	public void testWithIssuerDetails() throws ParseException {
		
		String issuerName = "XYZ Issuing Authority";
		CountryCode countryCode = new ISO3166_1Alpha2CountryCode("BG");
		IDDocumentDescription idDocumentDescription = new IDDocumentDescription(IDDocumentType.IDCARD, null, issuerName, countryCode, null, null);
		
		assertEquals(IDDocumentType.IDCARD, idDocumentDescription.getType());
		assertNull(idDocumentDescription.getNumber());
		assertEquals(issuerName, idDocumentDescription.getIssuerName());
		assertEquals(countryCode, idDocumentDescription.getIssuerCountry());
		assertNull(idDocumentDescription.getDateOfIssuance());
		assertNull(idDocumentDescription.getDateOfExpiry());
		
		JSONObject jsonObject = idDocumentDescription.toJSONObject();
		assertEquals(IDDocumentType.IDCARD.getValue(), jsonObject.get("type"));
		JSONObject issuerObject = JSONObjectUtils.getJSONObject(jsonObject, "issuer");
		assertEquals(issuerName, issuerObject.get("name"));
		assertEquals(countryCode.getValue(), issuerObject.get("country"));
		assertEquals(2, issuerObject.size());
		assertEquals(2, jsonObject.size());
		
		idDocumentDescription = IDDocumentDescription.parse(jsonObject);
		
		assertEquals(IDDocumentType.IDCARD, idDocumentDescription.getType());
		assertNull(idDocumentDescription.getNumber());
		assertEquals(issuerName, idDocumentDescription.getIssuerName());
		assertEquals(countryCode, idDocumentDescription.getIssuerCountry());
		assertNull(idDocumentDescription.getDateOfIssuance());
		assertNull(idDocumentDescription.getDateOfExpiry());
	}
	
	
	public void testComplete() throws ParseException {
		
		String number = "1628488669";
		String issuerName = "XYZ Issuing Authority";
		CountryCode countryCode = new ISO3166_1Alpha2CountryCode("BG");
		SimpleDate iat = new SimpleDate(2020, 3, 31);
		SimpleDate exp = new SimpleDate(2030, 3, 30);
		
		IDDocumentDescription idDocumentDescription = new IDDocumentDescription(IDDocumentType.IDCARD, number, issuerName, countryCode, iat, exp);
		
		assertEquals(IDDocumentType.IDCARD, idDocumentDescription.getType());
		assertEquals(number, idDocumentDescription.getNumber());
		assertEquals(issuerName, idDocumentDescription.getIssuerName());
		assertEquals(countryCode, idDocumentDescription.getIssuerCountry());
		assertEquals(iat, idDocumentDescription.getDateOfIssuance());
		assertEquals(exp, idDocumentDescription.getDateOfExpiry());
		
		JSONObject jsonObject = idDocumentDescription.toJSONObject();
		assertEquals(IDDocumentType.IDCARD.getValue(), jsonObject.get("type"));
		assertEquals(number, jsonObject.get("number"));
		JSONObject issuerObject = JSONObjectUtils.getJSONObject(jsonObject, "issuer");
		assertEquals(issuerName, issuerObject.get("name"));
		assertEquals(countryCode.getValue(), issuerObject.get("country"));
		assertEquals(2, issuerObject.size());
		assertEquals("2020-03-31", jsonObject.get("date_of_issuance"));
		assertEquals("2030-03-30", jsonObject.get("date_of_expiry"));
		assertEquals(5, jsonObject.size());
		
		idDocumentDescription = IDDocumentDescription.parse(jsonObject);
		
		assertEquals(IDDocumentType.IDCARD, idDocumentDescription.getType());
		assertEquals(number, idDocumentDescription.getNumber());
		assertEquals(issuerName, idDocumentDescription.getIssuerName());
		assertEquals(countryCode, idDocumentDescription.getIssuerCountry());
		assertEquals(iat, idDocumentDescription.getDateOfIssuance());
		assertEquals(exp, idDocumentDescription.getDateOfExpiry());
	}
}
