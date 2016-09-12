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

package com.nimbusds.oauth2.sdk.assertions.jwt;


import com.nimbusds.jose.JWSAlgorithm;
import junit.framework.TestCase;


/**
 * Tests the JWT assertion factory.
 */
public class JWTAssertionFactoryTest extends TestCase {


	public void testSupportedJWA() {

		assertTrue(JWTAssertionFactory.supportedJWAs().containsAll(JWSAlgorithm.Family.HMAC_SHA));
		assertTrue(JWTAssertionFactory.supportedJWAs().containsAll(JWSAlgorithm.Family.RSA));
		assertTrue(JWTAssertionFactory.supportedJWAs().containsAll(JWSAlgorithm.Family.EC));

		int algNum = JWSAlgorithm.Family.HMAC_SHA.size()
			+ JWSAlgorithm.Family.RSA.size()
			+ JWSAlgorithm.Family.EC.size();

		assertEquals(algNum, JWTAssertionFactory.supportedJWAs().size());
	}
}
