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


public class VouchTypeTest extends TestCase {


	public void testConstants() {
		
		assertEquals("written_attestation", VouchType.WRITTEN_ATTESTATION.getValue());
		assertEquals("digital_attestation", VouchType.DIGITAL_ATTESTATION.getValue());
	}
	
	
	public void testEqualityAndHashCode() {
		
		assertEquals(new VouchType("written_attestation"), VouchType.WRITTEN_ATTESTATION);
		assertEquals(new VouchType("written_attestation").hashCode(), VouchType.WRITTEN_ATTESTATION.hashCode());
	}
	
	
	public void testInequality() {
		
		assertNotSame(VouchType.WRITTEN_ATTESTATION, VouchType.DIGITAL_ATTESTATION);
		assertNotSame(VouchType.WRITTEN_ATTESTATION.hashCode(), VouchType.DIGITAL_ATTESTATION.hashCode());
	}
}
