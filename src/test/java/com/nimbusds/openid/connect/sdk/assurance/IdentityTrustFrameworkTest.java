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


import static org.junit.Assert.assertNotEquals;

import junit.framework.TestCase;


public class IdentityTrustFrameworkTest extends TestCase {
	
	
	public void testConstants() {
	
		assertEquals("de_aml", IdentityTrustFramework.DE_AML.getValue());
		assertEquals("eidas", IdentityTrustFramework.EIDAS.getValue());
		assertEquals("nist_800_63A", IdentityTrustFramework.NIST_800_63A.getValue());
		assertEquals("jp_aml", IdentityTrustFramework.JP_AML.getValue());
		assertEquals("jp_mpiupa", IdentityTrustFramework.JP_MPIUPA.getValue());
		assertEquals("cz_aml", IdentityTrustFramework.CZ_AML.getValue());
		assertEquals("de_tkg111", IdentityTrustFramework.DE_TKG111.getValue());
		assertEquals("be_itsme", IdentityTrustFramework.BE_ITSME.getValue());
		assertEquals("se_bankid", IdentityTrustFramework.SE_BANKID.getValue());
		assertEquals("it_spid", IdentityTrustFramework.IT_SPID.getValue());
		assertEquals("nl_eHerkenning", IdentityTrustFramework.NL_EHERKENNING.getValue());
		assertEquals("uk_tfida", IdentityTrustFramework.UK_TFIDA.getValue());
		assertEquals("au_tdif", IdentityTrustFramework.AU_TDIF.getValue());
		
		// deprecated
		assertEquals("eidas_ial_substantial", IdentityTrustFramework.EIDAS_IAL_SUBSTANTIAL.getValue());
		assertEquals("eidas_ial_high", IdentityTrustFramework.EIDAS_IAL_HIGH.getValue());
		
		assertEquals("nist_800_63A_ial_2", IdentityTrustFramework.NIST_800_63A_IAL_2.getValue());
		assertEquals("nist_800_63A_ial_3", IdentityTrustFramework.NIST_800_63A_IAL_3.getValue());
	}
	
	
	public void testValue() {
		
		String value = "tf0001";
		IdentityTrustFramework tf = new IdentityTrustFramework(value);
		assertEquals(value, tf.getValue());
		
		assertEquals(tf, new IdentityTrustFramework(value));
	}
	
	
	public void testInequality() {
		
		assertNotEquals(new IdentityTrustFramework("tf01"), new IdentityTrustFramework("TF01"));
	}
}
