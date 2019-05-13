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

package com.nimbusds.openid.connect.sdk.op;


import java.net.URI;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

import junit.framework.TestCase;


/**
 * Tests the resolve exception.
 */
public class ResolveExceptionTest extends TestCase{
	

	public void testWithErrorObject_minimalTopLevelRequest() {

		ErrorObject errorObject = OAuth2Error.REQUEST_URI_NOT_SUPPORTED;

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			ResponseType.getDefault(),
			new Scope("openid"),
			new ClientID("123"),
			null)
			.requestURI(URI.create("https://example.com/oidc/request-object.jwt"))
			.build();

		ResolveException e = new ResolveException(errorObject, request);

		assertEquals(errorObject.getDescription(), e.getMessage());
		assertEquals(errorObject, e.getErrorObject());
		assertEquals(request.getClientID(), e.getClientID());
		assertNull(e.getRedirectionURI()); // return error to registered redirect_uri
		assertNull(e.getState());
		assertNull(e.getResponseMode());
		assertNull(e.getCause());
	}


	public void testWithErrorObject_completeTopLevelRequest() {

		ErrorObject errorObject = OAuth2Error.REQUEST_URI_NOT_SUPPORTED;

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			ResponseType.getDefault(),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.state(new State("xyz"))
			.responseMode(ResponseMode.FORM_POST)
			.requestURI(URI.create("https://example.com/oidc/request-object.jwt"))
			.build();

		ResolveException e = new ResolveException(errorObject, request);

		assertEquals(errorObject.getDescription(), e.getMessage());
		assertEquals(errorObject, e.getErrorObject());
		assertEquals(request.getClientID(), e.getClientID());
		assertEquals(request.getRedirectionURI(), e.getRedirectionURI());
		assertEquals(request.getState(), e.getState());
		assertEquals(request.getResponseMode(), e.getResponseMode());
		assertNull(e.getCause());
	}


	public void testResolveRequestURINotSupportedError() {

		String exMessage = "Invalid JWT: Signature validation failed";
		String clientMessage = "Invalid JWT";
		AuthenticationRequest request = new AuthenticationRequest.Builder(
			ResponseType.getDefault(),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.state(new State("xyz"))
			.responseMode(ResponseMode.FORM_POST)
			.requestURI(URI.create("https://example.com/oidc/request-object.jwt"))
			.build();

		ResolveException e = new ResolveException(exMessage, clientMessage, request, null);

		assertEquals(exMessage, e.getMessage());
		assertEquals(OAuth2Error.INVALID_REQUEST_URI.getCode(), e.getErrorObject().getCode());
		assertEquals(clientMessage, e.getErrorObject().getDescription());
		assertEquals(request.getClientID(), e.getClientID());
		assertEquals(request.getRedirectionURI(), e.getRedirectionURI());
		assertEquals(request.getState(), e.getState());
		assertEquals(request.getResponseMode(), e.getResponseMode());
		assertNull(e.getCause());
	}


	public void testResolveRequestObjectNotSupportedError() {

		String exMessage = "Invalid JWT: Signature validation failed";
		String clientMessage = "Invalid JWT";
		PlainJWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
			.claim("scope", "openid email profile")
			.claim("redirect_uri", "https://example.com/cb")
			.build());
		AuthenticationRequest request = new AuthenticationRequest.Builder(
			ResponseType.getDefault(),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.state(new State("xyz"))
			.responseMode(ResponseMode.FORM_POST)
			.requestObject(jwt)
			.build();

		ResolveException e = new ResolveException(exMessage, clientMessage, request, null);

		assertEquals(exMessage, e.getMessage());
		assertEquals(OAuth2Error.INVALID_REQUEST_OBJECT.getCode(), e.getErrorObject().getCode());
		assertEquals(clientMessage, e.getErrorObject().getDescription());
		assertEquals(request.getClientID(), e.getClientID());
		assertEquals(request.getRedirectionURI(), e.getRedirectionURI());
		assertEquals(request.getState(), e.getState());
		assertEquals(request.getResponseMode(), e.getResponseMode());
		assertNull(e.getCause());
	}


	public void testResolveRequestObjectNotSupportedError_withCause() {

		String exMessage = "Invalid JWT: Signature validation failed";
		String clientMessage = "Invalid JWT";
		PlainJWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
			.claim("scope", "openid email profile")
			.claim("redirect_uri", "https://example.com/cb")
			.build());
		AuthenticationRequest request = new AuthenticationRequest.Builder(
			ResponseType.getDefault(),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.state(new State("xyz"))
			.responseMode(ResponseMode.FORM_POST)
			.requestObject(jwt)
			.build();
		Throwable cause = new Exception("Bad RSA signature");

		ResolveException e = new ResolveException(exMessage, clientMessage, request, cause);

		assertEquals(exMessage, e.getMessage());
		assertEquals(OAuth2Error.INVALID_REQUEST_OBJECT.getCode(), e.getErrorObject().getCode());
		assertEquals(clientMessage, e.getErrorObject().getDescription());
		assertEquals(request.getClientID(), e.getClientID());
		assertEquals(request.getRedirectionURI(), e.getRedirectionURI());
		assertEquals(request.getState(), e.getState());
		assertEquals(request.getResponseMode(), e.getResponseMode());
		assertEquals(cause, e.getCause());
	}


	public void testResolveRequestObjectNotSupportedError_defaultClientDescription() {

		String exMessage = "Invalid JWT: Signature validation failed";
		String clientMessage = null;
		PlainJWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
			.claim("scope", "openid email profile")
			.claim("redirect_uri", "https://example.com/cb")
			.build());
		AuthenticationRequest request = new AuthenticationRequest.Builder(
			ResponseType.getDefault(),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.state(new State("xyz"))
			.responseMode(ResponseMode.FORM_POST)
			.requestObject(jwt)
			.build();
		Throwable cause = new Exception("Bad RSA signature");

		ResolveException e = new ResolveException(exMessage, clientMessage, request, cause);

		assertEquals(exMessage, e.getMessage());
		assertEquals(OAuth2Error.INVALID_REQUEST_OBJECT.getCode(), e.getErrorObject().getCode());
		assertEquals(OAuth2Error.INVALID_REQUEST_OBJECT.getDescription(), e.getErrorObject().getDescription());
		assertEquals(request.getClientID(), e.getClientID());
		assertEquals(request.getRedirectionURI(), e.getRedirectionURI());
		assertEquals(request.getState(), e.getState());
		assertEquals(request.getResponseMode(), e.getResponseMode());
		assertEquals(cause, e.getCause());
	}
}
