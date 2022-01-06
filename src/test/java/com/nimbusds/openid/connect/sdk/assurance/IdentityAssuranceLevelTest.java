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

package com.nimbusds.openid.connect.sdk.assurance;


import junit.framework.TestCase;


public class IdentityAssuranceLevelTest extends TestCase {
	
	
	public void testConstants() {
	
		assertEquals("very_low", IdentityAssuranceLevel.VERY_LOW.getValue());
		assertEquals("low", IdentityAssuranceLevel.LOW.getValue());
		assertEquals("medium", IdentityAssuranceLevel.MEDIUM.getValue());
		assertEquals("substantial", IdentityAssuranceLevel.SUBSTANTIAL.getValue());
		assertEquals("high", IdentityAssuranceLevel.HIGH.getValue());
		assertEquals("very_high", IdentityAssuranceLevel.VERY_HIGH.getValue());
		assertEquals("ial1", IdentityAssuranceLevel.IAL1.getValue());
		assertEquals("ial2", IdentityAssuranceLevel.IAL2.getValue());
		assertEquals("ial3", IdentityAssuranceLevel.IAL3.getValue());
		assertEquals("al2", IdentityAssuranceLevel.AL2.getValue());
		assertEquals("al3", IdentityAssuranceLevel.AL3.getValue());
	}
	
	
	public void testConstructor() {
		
		String value = "level-x";
		IdentityAssuranceLevel level = new IdentityAssuranceLevel(value);
		assertEquals(value, level.getValue());
	}
	
	
	public void testEquality() {
		
		assertEquals(new IdentityAssuranceLevel("level-x"), new IdentityAssuranceLevel("level-x"));
		assertEquals(new IdentityAssuranceLevel("level-x").hashCode(), new IdentityAssuranceLevel("level-x").hashCode());
	}
	
	
	public void testInequality() {
		
		assertNotSame(new IdentityAssuranceLevel("level-x"), new IdentityAssuranceLevel("level-y"));
		assertNotSame(new IdentityAssuranceLevel("level-x").hashCode(), new IdentityAssuranceLevel("level-y").hashCode());
	}
}
