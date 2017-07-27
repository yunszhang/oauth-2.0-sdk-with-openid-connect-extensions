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

package com.nimbusds.openid.connect.sdk.validators;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.claims.StateHash;
import junit.framework.TestCase;


/**
 * Tests the state hash validator.
 */
public class StateValidatorTest extends TestCase {
	
	
	public void testValid()
		throws InvalidHashException {
		
		State state = new State();
		StateHash sHash = StateHash.compute(state, JWSAlgorithm.HS256);
		StateValidator.validate(state, JWSAlgorithm.HS256, sHash);
	}
	
	
	public void testUnsupportedAlg() {
		
		State state = new State();
		StateHash sHash = StateHash.compute(state, JWSAlgorithm.HS256);
		try {
			StateValidator.validate(state, new JWSAlgorithm("none"), sHash);
			fail();
		} catch (InvalidHashException e) {
			assertEquals("State hash (s_hash) mismatch", e.getMessage());
		}
	}
	
	
	public void testInvalidHash() {
	
		State state = new State();
		try {
			StateValidator.validate(state, JWSAlgorithm.HS256, new StateHash("xxx"));
			fail();
		} catch (InvalidHashException e) {
			assertEquals("State hash (s_hash) mismatch", e.getMessage());
		}
	}
}
