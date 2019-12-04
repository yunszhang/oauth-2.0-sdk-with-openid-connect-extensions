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

package com.nimbusds.openid.connect.sdk.assurance;


import junit.framework.TestCase;

import com.nimbusds.openid.connect.sdk.assurance.evidences.IdentityVerificationMethod;


public class IdentityVerificationMethodTest extends TestCase {
	
	
	public void testConstants() {
		
		assertEquals("eid", IdentityVerificationMethod.EID.getValue());
		assertEquals("pipp", IdentityVerificationMethod.PIPP.getValue());
		assertEquals("sripp", IdentityVerificationMethod.SRIPP.getValue());
		assertEquals("uripp", IdentityVerificationMethod.URIPP.getValue());
	}
	
	
	public void testValue() {
		
		String value = "abc";
		assertEquals(value, new IdentityVerificationMethod(value).getValue());
		assertTrue(new IdentityVerificationMethod(value).equals(new IdentityVerificationMethod(value)));
	}
}
