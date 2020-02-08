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


import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;


public class ClaimsSetTest extends TestCase {
	
	
	public void testAudienceList() throws ParseException {
		
		ClaimsSet claimsSet = new ClaimsSet();
		
		assertNull(claimsSet.getAudience());
		
		List<Audience> audienceList = new Audience("123").toSingleAudienceList();
		claimsSet.setAudience(audienceList);
		assertEquals(audienceList, claimsSet.getAudience());
		
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		assertEquals(Collections.singletonList("123"), jwtClaimsSet.getAudience());
		assertEquals(1, jwtClaimsSet.getClaims().size());
	}
}
