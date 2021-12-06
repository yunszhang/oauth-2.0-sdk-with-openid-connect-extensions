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

import com.nimbusds.openid.connect.sdk.assurance.evidences.VerificationMethodType;


public class VerificationMethodTypeTest extends TestCase {
	
	
	public void testConstants() {
		
		assertEquals("auth", VerificationMethodType.AUTH.getValue());
		assertEquals("token", VerificationMethodType.TOKEN.getValue());
		assertEquals("kbv", VerificationMethodType.KBV.getValue());
		assertEquals("pvp", VerificationMethodType.PVP.getValue());
		assertEquals("pvr", VerificationMethodType.PVR.getValue());
	}
	
	
	public void testValue() {
		
		String value = "abc";
		assertEquals(value, new VerificationMethodType(value).getValue());
		assertEquals(new VerificationMethodType(value), new VerificationMethodType(value));
		assertEquals(new VerificationMethodType(value).hashCode(), new VerificationMethodType(value).hashCode());
	}
}
