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


public class ElectronicRecordTypeTest extends TestCase {
	
	
	
	public void testConstants() {
		
		assertEquals("birth_register", ElectronicRecordType.BIRTH_REGISTER.getValue());
		assertEquals("population_register", ElectronicRecordType.POPULATION_REGISTER.getValue());
		assertEquals("voter_register", ElectronicRecordType.VOTER_REGISTER.getValue());
		assertEquals("adoption_register", ElectronicRecordType.ADOPTION_REGISTER.getValue());
		assertEquals("marriage_register", ElectronicRecordType.MARRIAGE_REGISTER.getValue());
		assertEquals("education", ElectronicRecordType.EDUCATION.getValue());
		assertEquals("military", ElectronicRecordType.MILITARY.getValue());
		assertEquals("bank_account", ElectronicRecordType.BANK_ACCOUNT.getValue());
		assertEquals("utility_account", ElectronicRecordType.UTILITY_ACCOUNT.getValue());
		assertEquals("mortgage_account", ElectronicRecordType.MORTGAGE_ACCOUNT.getValue());
		assertEquals("loan_account", ElectronicRecordType.LOAN_ACCOUNT.getValue());
		assertEquals("tax", ElectronicRecordType.TAX.getValue());
		assertEquals("social_security", ElectronicRecordType.SOCIAL_SECURITY.getValue());
		assertEquals("prison_record", ElectronicRecordType.PRISON_RECORD.getValue());
	}


	public void testConstructor() {
		
		String value = "some_register";
		ElectronicRecordType type = new ElectronicRecordType(value);
		assertEquals(value, type.getValue());
		
		assertEquals(type, new ElectronicRecordType(value));
		assertEquals(type.hashCode(), new ElectronicRecordType(value).hashCode());
	}
	
	
	public void testInequality() {
		
		ElectronicRecordType a = new ElectronicRecordType("a");
		ElectronicRecordType b = new ElectronicRecordType("b");
		
		assertNotSame(a, b);
		assertNotSame(a.hashCode(), b.hashCode());
	}
}
