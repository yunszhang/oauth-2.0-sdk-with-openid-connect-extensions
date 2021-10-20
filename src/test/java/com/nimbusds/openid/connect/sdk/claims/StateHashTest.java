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


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.junit.Assert.assertNotEquals;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.oauth2.sdk.id.State;


public class StateHashTest extends TestCase {
	
	
	public void testCompute()
		throws Exception {
		
		State state = new State("abc");
		
		MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
		byte[] hash = sha512.digest(state.getValue().getBytes(StandardCharsets.US_ASCII));
		
		assertEquals(512, ByteUtils.bitLength(hash));
		
		byte[] truncatedHash = ByteUtils.subArray(hash, 0, hash.length / 2);
		
		assertEquals(256, ByteUtils.bitLength(truncatedHash));
		
		assertEquals(Base64URL.encode(truncatedHash).toString(), StateHash.compute(state, JWSAlgorithm.HS512).getValue());
		assertEquals(Base64URL.encode(truncatedHash).toString(), StateHash.compute(state, JWSAlgorithm.HS512, null).getValue());
	}
	
	
	// https://bitbucket.org/openid/connect/issues/1125/_hash-algorithm-for-eddsa-id-tokens#comment-57040192
	public void testComputeWithSHA512_EdDSA() {
		
		State state = new State("YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL");
		
		StateHash expectedHash = new StateHash("p2LHG4H-8pYDc0hyVOo3iIHvZJUqe9tbj3jESOuXbkY");
		
		assertEquals(expectedHash, StateHash.compute(state, JWSAlgorithm.EdDSA, Curve.Ed25519));
	}
	
	
	public void testEquality() {
		
		assertEquals(new StateHash("abc"), new StateHash("abc"));
	}
	
	
	public void testInequality() {
		
		assertNotEquals(new StateHash("abc"), new StateHash("ABC"));
		assertNotEquals(null, new StateHash("abc"));
	}
	
	
	public void testUnsupportedJWSAlg() {
		
		assertNull(StateHash.compute(new State(), new JWSAlgorithm("no-such-alg")));
		assertNull(StateHash.compute(new State(), new JWSAlgorithm("no-such-alg"), null));
	}
}
