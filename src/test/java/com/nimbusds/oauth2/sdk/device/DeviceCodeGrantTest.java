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

package com.nimbusds.oauth2.sdk.device;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;

import junit.framework.TestCase;

/**
 * Tests the device code grant class.
 */
public class DeviceCodeGrantTest extends TestCase {

	public void testConstructor() throws Exception {

		DeviceCode code = new DeviceCode("abc");

		DeviceCodeGrant grant = new DeviceCodeGrant(code);

		assertEquals(code, grant.getDeviceCode());

		assertEquals(GrantType.DEVICE_CODE, grant.getType());

		Map<String, List<String>> params = grant.toParameters();
		assertEquals(Collections.singletonList("abc"), params.get("device_code"));
		assertEquals(Collections.singletonList("urn:ietf:params:oauth:grant-type:device_code"),
		                params.get("grant_type"));
		assertEquals(2, params.size());

		grant = DeviceCodeGrant.parse(params);
		assertEquals(code, grant.getDeviceCode());
		assertEquals(GrantType.DEVICE_CODE, grant.getType());
	}


	public void testParse() throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.DEVICE_CODE.getValue()));
		params.put("device_code", Collections.singletonList("abc"));

		DeviceCodeGrant grant = DeviceCodeGrant.parse(params);

		assertEquals(GrantType.DEVICE_CODE, grant.getType());
		assertEquals("abc", grant.getDeviceCode().getValue());
	}


	public void testParseMissingGrantType() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", null);
		params.put("device_code", Collections.singletonList("abc"));

		try {
			DeviceCodeGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing grant_type parameter",
			                e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseUnsupportedGrant() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("no-such-grant"));
		params.put("device_code", Collections.singletonList("abc"));

		try {
			AuthorizationCodeGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode(), e.getErrorObject().getCode());
			assertEquals("Unsupported grant type: The grant_type must be authorization_code",
			                e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseMissingCode() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.DEVICE_CODE.getValue()));
		params.put("device_code", Collections.singletonList(""));

		try {
			DeviceCodeGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing or empty device_code parameter",
			                e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testEquality() {

		assertTrue(new DeviceCodeGrant(new DeviceCode("xyz"))
		                .equals(new DeviceCodeGrant(new DeviceCode("xyz"))));
	}


	public void testInequality() {

		assertFalse(new DeviceCodeGrant(new DeviceCode("xyz"))
		                .equals(new DeviceCodeGrant(new DeviceCode("abc"))));
	}
}
