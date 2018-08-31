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

package com.nimbusds.oauth2.sdk;


import java.util.Collections;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the SAML 2.0 bearer grant.
 */
public class SAML2BearerGrantTest extends TestCase {


	public void testConstructorAndParser()
		throws Exception {

		Base64URL assertion = new Base64URL("abc"); // dummy XML assertion

		SAML2BearerGrant grant = new SAML2BearerGrant(assertion);
		assertEquals(GrantType.SAML2_BEARER, grant.getType());
		assertEquals(assertion, grant.getSAML2Assertion());
		assertEquals("abc", grant.getAssertion());

		Map<String,List<String>> params = grant.toParameters();
		assertEquals(Collections.singletonList(GrantType.SAML2_BEARER.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("abc"), params.get("assertion"));
		assertEquals(2, params.size());

		grant = SAML2BearerGrant.parse(params);
		assertEquals(GrantType.SAML2_BEARER, grant.getType());
		assertEquals("abc", grant.getSAML2Assertion().toString());
		assertEquals("abc", grant.getAssertion());
	}
}
