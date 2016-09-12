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


import java.net.URI;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;


/**
 * Tests the general exception class.
 */
public class GeneralExceptionTest extends TestCase {


	public void testConstructor1() {

		GeneralException e = new GeneralException("message");
		assertEquals("message", e.getMessage());

		assertNull(e.getErrorObject());
		assertNull(e.getClientID());
		assertNull(e.getRedirectionURI());
		assertNull(e.getState());
	}


	public void testConstructor2() {

		GeneralException e = new GeneralException("message", new IllegalArgumentException());
		assertEquals("message", e.getMessage());

		assertNull(e.getErrorObject());
		assertNull(e.getClientID());
		assertNull(e.getRedirectionURI());
		assertNull(e.getState());
	}


	public void testConstructor3() {

		GeneralException e = new GeneralException("message", OAuth2Error.INVALID_REQUEST, new IllegalArgumentException());
		assertEquals("message", e.getMessage());

		assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		assertNull(e.getClientID());
		assertNull(e.getRedirectionURI());
		assertNull(e.getState());
	}


	public void testConstructor4()
		throws Exception {

		GeneralException e = new GeneralException(
			"message",
			OAuth2Error.INVALID_REQUEST,
			new ClientID("abc"),
			new URI("https://redirect.com"),
			ResponseMode.QUERY,
			new State("123"));

		assertEquals("message", e.getMessage());
		assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		assertEquals("abc", e.getClientID().getValue());
		assertEquals("https://redirect.com", e.getRedirectionURI().toString());
		assertEquals(ResponseMode.QUERY, e.getResponseMode());
		assertEquals("123", e.getState().getValue());
	}


	public void testConstructor5()
		throws Exception {

		GeneralException e = new GeneralException(
			"message",
			OAuth2Error.INVALID_REQUEST,
			new ClientID("abc"),
			new URI("https://redirect.com"),
			ResponseMode.FRAGMENT,
			new State("123"),
			new IllegalArgumentException());

		assertEquals("message", e.getMessage());
		assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		assertEquals("abc", e.getClientID().getValue());
		assertEquals("https://redirect.com", e.getRedirectionURI().toString());
		assertEquals(ResponseMode.FRAGMENT, e.getResponseMode());
		assertEquals("123", e.getState().getValue());
	}


	public void testErrorObjectConstructor() {

		GeneralException e = new GeneralException(OAuth2Error.INVALID_GRANT.setDescription("Invalid code"));

		assertEquals("Invalid code", e.getMessage());
		assertEquals(OAuth2Error.INVALID_GRANT.getCode(), e.getErrorObject().getCode());
		assertEquals("Invalid code", e.getErrorObject().getDescription());
	}
}
