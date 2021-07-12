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

package com.nimbusds.oauth2.sdk.dpop.verifier;


import java.util.AbstractMap;
import java.util.Map;

import junit.framework.TestCase;
import org.junit.After;
import org.junit.Before;

import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.singleuse.AlreadyUsedException;


public class DefaultDPoPSingleUseCheckerTest extends TestCase {
	
	
	DefaultDPoPSingleUseChecker checker;
	
	
	public static final long LIFETIME_SECONDS = 2;
	
	
	public static final long PURGE_INTERVAL_SECONDS = 3;
	
	
	@Before
	@Override
	public void setUp()
		throws Exception {
		
		super.setUp();
		
		checker = new DefaultDPoPSingleUseChecker(
			LIFETIME_SECONDS,
			PURGE_INTERVAL_SECONDS
		);
	}
	
	
	@After
	@Override
	public void tearDown()
		throws Exception {
		
		super.tearDown();
		
		if (checker == null) {
			return;
		}
		
		checker.shutdown();
	}
	

	public void testRun() throws AlreadyUsedException, InterruptedException {
		
		assertEquals(0, checker.getCacheSize());
		
		DPoPIssuer issuer = new DPoPIssuer("client-123");
		JWTID jti = new JWTID(12);
		
		Map.Entry<DPoPIssuer, JWTID> en = new AbstractMap.SimpleImmutableEntry<>(
			issuer,
			jti
		);
		
		checker.markAsUsed(en);
		
		assertEquals(1, checker.getCacheSize());
		
		// Replay
		try {
			checker.markAsUsed(en);
			fail();
		} catch (AlreadyUsedException e) {
			assertEquals("Detected jti replay", e.getMessage());
		}
		
		Thread.sleep(PURGE_INTERVAL_SECONDS * 1000 * 2);
		
		assertEquals(0, checker.getCacheSize());
		
		checker.markAsUsed(en);
		
		assertEquals(1, checker.getCacheSize());
		
		// Replay
		try {
			checker.markAsUsed(en);
			fail();
		} catch (AlreadyUsedException e) {
			assertEquals("Detected jti replay", e.getMessage());
		}
	}
}
