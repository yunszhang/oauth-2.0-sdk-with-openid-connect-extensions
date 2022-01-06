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
import com.nimbusds.openid.connect.sdk.claims.Address;


public class VoucherTest extends TestCase {

	public void testMinimal()
		throws ParseException {
		
		Voucher voucher = new Voucher(null, null, null, null, null);
		
		assertNull(voucher.getName());
		assertNull(voucher.getBirthdateString());
		assertNull(voucher.getAddress());
		assertNull(voucher.getOccupation());
		assertNull(voucher.getOrganization());
		
		JSONObject jsonObject = voucher.toJSONObject();
		assertTrue(jsonObject.isEmpty());
		
		voucher = Voucher.parse(jsonObject);
		
		assertNull(voucher.getName());
		assertNull(voucher.getBirthdateString());
		assertNull(voucher.getAddress());
		assertNull(voucher.getOccupation());
		assertNull(voucher.getOrganization());
		
		assertEquals("Equality", voucher, Voucher.parse(jsonObject));
		assertEquals("Hash code", voucher.hashCode(), Voucher.parse(jsonObject).hashCode());
	}
	
	
	public void testFullySet()
		throws ParseException {
		
		Name name = new Name("Some Name");
		String birthdate = "1950-12-31";
		Address address = new Address();
		address.setPostalCode("4000");
		address.setCountry("Bulgaria");
		Occupation occupation = new Occupation("Some occupation");
		Organization organization = new Organization("Some organization");
		
		Voucher voucher = new Voucher(name, birthdate, address, occupation, organization);
		
		assertEquals(name, voucher.getName());
		assertEquals(birthdate, voucher.getBirthdateString());
		assertEquals(address, voucher.getAddress());
		assertEquals(occupation, voucher.getOccupation());
		assertEquals(organization, voucher.getOrganization());
		
		JSONObject jsonObject = voucher.toJSONObject();
		assertEquals(name.getValue(), jsonObject.get("name"));
		assertEquals(birthdate, jsonObject.get("birthdate"));
		assertEquals(address.getPostalCode(), jsonObject.get("postal_code"));
		assertEquals(address.getCountry(), jsonObject.get("country"));
		assertEquals(occupation.getValue(), jsonObject.get("occupation"));
		assertEquals(organization.getValue(), jsonObject.get("organization"));
		assertEquals(6, jsonObject.size());
		
		voucher = Voucher.parse(jsonObject);
		
		assertEquals(name, voucher.getName());
		assertEquals(birthdate, voucher.getBirthdateString());
		assertEquals(address, voucher.getAddress());
		assertEquals(occupation, voucher.getOccupation());
		assertEquals(organization, voucher.getOrganization());
		
		assertEquals("Equality", voucher, Voucher.parse(jsonObject));
		assertEquals("Hash code", voucher.hashCode(), Voucher.parse(jsonObject).hashCode());
	}
}
