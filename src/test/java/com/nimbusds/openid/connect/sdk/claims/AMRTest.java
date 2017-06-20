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

package com.nimbusds.openid.connect.sdk.claims;


import junit.framework.TestCase;


/**
 * Tests the AMR class.
 */
public class AMRTest extends TestCase {
	

	public void testConstants() {

		assertEquals("face", AMR.FACE.getValue());
		assertEquals("fpt", AMR.FPT.getValue());
		assertEquals("geo", AMR.GEO.getValue());
		assertEquals("hwk", AMR.HWK.getValue());
		assertEquals("iris", AMR.IRIS.getValue());
		assertEquals("kba", AMR.KBA.getValue());
		assertEquals("mca", AMR.MCA.getValue());
		assertEquals("mfa", AMR.MFA.getValue());
		assertEquals("otp", AMR.OTP.getValue());
		assertEquals("pin", AMR.PIN.getValue());
		assertEquals("pwd", AMR.PWD.getValue());
		assertEquals("rba", AMR.RBA.getValue());
		assertEquals("sc", AMR.SC.getValue());
		assertEquals("sms", AMR.SMS.getValue());
		assertEquals("tel", AMR.TEL.getValue());
		assertEquals("user", AMR.USER.getValue());
		assertEquals("vbm", AMR.VBM.getValue());
		assertEquals("wia", AMR.WIA.getValue());
		
		// deprecated
		assertEquals("pop", AMR.POP.getValue());
		assertEquals("eye", AMR.EYE.getValue());
	}
}
