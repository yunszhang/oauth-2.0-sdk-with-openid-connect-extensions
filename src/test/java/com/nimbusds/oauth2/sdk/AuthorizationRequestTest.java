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


import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.*;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import junit.framework.TestCase;


public class AuthorizationRequestTest extends TestCase {


	public void testRegisteredParameters() {

		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("response_type"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("response_mode"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("client_id"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("redirect_uri"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("scope"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("state"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("code_challenge"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("code_challenge_method"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("resource"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("include_granted_scopes"));
		assertEquals(10, AuthorizationRequest.getRegisteredParameterNames().size());
	}
	
	
	public void testMinimal()
		throws Exception {
		
		URI uri = new URI("https://c2id.com/authz/");

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ClientID clientID = new ClientID("123456");

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());

		assertNull(req.getRedirectionURI());
		assertNull(req.getScope());
		assertNull(req.getState());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		
		assertNull(req.getResources());
		
		assertFalse(req.includeGrantedScopes());

		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());

		String query = req.toQueryString();

		System.out.println("Authorization query: " + query);

		Map<String,List<String>> params = URLUtils.parseParameters(query);
		assertEquals(Collections.singletonList("code"), params.get("response_type"));
		assertEquals(Collections.singletonList("123456"), params.get("client_id"));
		assertEquals(2, params.size());

		HTTPRequest httpReq = req.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpReq.getMethod());
		assertEquals(uri, httpReq.getURL().toURI());
		assertEquals(query, httpReq.getQuery());

		req = AuthorizationRequest.parse(uri, query);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());

		assertNull(req.getResponseMode());
		assertNull(req.getRedirectionURI());
		assertNull(req.getScope());
		assertNull(req.getState());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		assertNull(req.getResources());
		assertFalse(req.includeGrantedScopes());

		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());
	}


	public void testMinimalAltParse()
		throws Exception {

		URI uri = new URI("https://c2id.com/authz/");

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ClientID clientID = new ClientID("123456");

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID);

		String query = req.toQueryString();

		req = AuthorizationRequest.parse(query);

		assertNull(req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());
		assertNull(req.getResponseMode());
		assertNull(req.getRedirectionURI());
		assertNull(req.getScope());
		assertNull(req.getState());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		assertNull(req.getResources());
		assertFalse(req.includeGrantedScopes());
		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());
	}


	public void testToRequestURIWithParse()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ResponseType rts = new ResponseType("code");
		ClientID clientID = new ClientID("123456");
		URI endpointURI = new URI("https://c2id.com/login");

		AuthorizationRequest req = new AuthorizationRequest.Builder(rts, clientID).
			redirectionURI(redirectURI).
			endpointURI(endpointURI).
			build();

		URI requestURI = req.toURI();

		assertTrue(requestURI.toString().startsWith(endpointURI.toString() + "?"));
		req = AuthorizationRequest.parse(requestURI);

		assertEquals(endpointURI, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		assertNull(req.getScope());
		assertNull(req.getState());
		assertNull(req.getResources());
		assertFalse(req.includeGrantedScopes());
		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());
	}


	public void testFull()
		throws Exception {

		URI uri = new URI("https://c2id.com/authz/");

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ResponseMode rm = ResponseMode.FORM_POST;

		ClientID clientID = new ClientID("123456");

		URI redirectURI = new URI("https://example.com/oauth2/");

		Scope scope = Scope.parse("read write");

		State state = new State();

		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
		CodeChallenge codeChallenge = CodeChallenge.compute(codeChallengeMethod, codeVerifier);
		
		List<URI> resources = Arrays.asList(URI.create("https://rs1.com"), URI.create("https://rs2.com"));

		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));
		customParams.put("z", Collections.singletonList("300"));


		AuthorizationRequest req = new AuthorizationRequest(uri, rts, rm, clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, resources, true, customParams);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(rm, req.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, req.impliedResponseMode());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());
		assertEquals(resources, req.getResources());

		String query = req.toQueryString();

		System.out.println("Authorization query: " + query);

		Map<String,List<String>> params = URLUtils.parseParameters(query);

		assertEquals(Collections.singletonList("code"), params.get("response_type"));
		assertEquals(Collections.singletonList("form_post"), params.get("response_mode"));
		assertEquals(Collections.singletonList("123456"), params.get("client_id"));
		assertEquals(Collections.singletonList(redirectURI.toString()), params.get("redirect_uri"));
		assertEquals(Collections.singletonList(scope.toString()), params.get("scope"));
		assertEquals(Collections.singletonList(state.getValue()), params.get("state"));
		assertEquals(Collections.singletonList(codeChallenge.getValue()), params.get("code_challenge"));
		assertEquals(Collections.singletonList(codeChallengeMethod.getValue()), params.get("code_challenge_method"));
		assertEquals(Arrays.asList("https://rs1.com", "https://rs2.com"), params.get("resource"));
		assertEquals(Collections.singletonList("true"), params.get("include_granted_scopes"));
		assertEquals(Collections.singletonList("100"), params.get("x"));
		assertEquals(Collections.singletonList("200"), params.get("y"));
		assertEquals(Collections.singletonList("300"), params.get("z"));
		assertEquals(13, params.size());

		HTTPRequest httpReq = req.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpReq.getMethod());
		assertEquals(query, httpReq.getQuery());

		req = AuthorizationRequest.parse(uri, query);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(rm, req.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, req.impliedResponseMode());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());
		assertEquals(codeChallenge, req.getCodeChallenge());
		assertEquals(codeChallengeMethod, req.getCodeChallengeMethod());
		assertEquals(resources, req.getResources());
		assertTrue(req.includeGrantedScopes());
		assertEquals(Collections.singletonList("100"), req.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), req.getCustomParameter("y"));
		assertEquals(Collections.singletonList("300"), req.getCustomParameter("z"));
		assertEquals(Collections.singletonList("100"), req.getCustomParameters().get("x"));
		assertEquals(Collections.singletonList("200"), req.getCustomParameters().get("y"));
		assertEquals(Collections.singletonList("300"), req.getCustomParameters().get("z"));
		assertEquals(3, req.getCustomParameters().size());
	}


	public void testFullAltParse()
		throws Exception {

		URI uri = new URI("https://c2id.com/authz/");
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ClientID clientID = new ClientID("123456");

		URI redirectURI = new URI("https://example.com/oauth2/");

		Scope scope = Scope.parse("read write");

		State state = new State();

		CodeVerifier verifier = new CodeVerifier();
		CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.PLAIN, verifier);
		
		List<URI> resources = Collections.singletonList(URI.create("https://rs1.com"));

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, null, clientID, redirectURI, scope, state, codeChallenge, null, resources, false, null);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());
		assertEquals(resources, req.getResources());

		String query = req.toQueryString();

		req = AuthorizationRequest.parse(query);

		assertNull(req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());
		assertEquals(codeChallenge, req.getCodeChallenge());
		assertEquals(resources, req.getResources());
		assertFalse(req.includeGrantedScopes());
		assertNull(req.getCodeChallengeMethod());
	}


	public void testBuilderMinimal() {

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123")).build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertNull(request.getEndpointURI());
		assertNull(request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.QUERY, request.impliedResponseMode());
		assertNull(request.getScope());
		assertNull(request.getState());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertNull(request.getResources());
		assertFalse(request.includeGrantedScopes());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderMinimalAlt() {

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("token"), new ClientID("123")).build();
		
		assertEquals(new ResponseType("token"), request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertNull(request.getEndpointURI());
		assertNull(request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, request.impliedResponseMode());
		assertNull(request.getScope());
		assertNull(request.getState());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertFalse(request.includeGrantedScopes());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderMinimalNullCodeChallenge() {

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("token"), new ClientID("123"))
			.codeChallenge((CodeVerifier) null, null)
			.build();
		
		assertEquals(new ResponseType("token"), request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertNull(request.getEndpointURI());
		assertNull(request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, request.impliedResponseMode());
		assertNull(request.getScope());
		assertNull(request.getState());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertFalse(request.includeGrantedScopes());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderMinimalNullCodeChallenge_deprecated() {

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("token"), new ClientID("123"))
			.codeChallenge((CodeChallenge) null, null)
			.build();
		
		assertEquals(new ResponseType("token"), request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertNull(request.getEndpointURI());
		assertNull(request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, request.impliedResponseMode());
		assertNull(request.getScope());
		assertNull(request.getState());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertFalse(request.includeGrantedScopes());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderFull()
		throws Exception {

		CodeVerifier codeVerifier = new CodeVerifier();

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
			.endpointURI(new URI("https://c2id.com/login"))
			.redirectionURI(new URI("https://client.com/cb"))
			.scope(new Scope("openid", "email"))
			.state(new State("123"))
			.responseMode(ResponseMode.FORM_POST)
			.codeChallenge(codeVerifier, CodeChallengeMethod.S256)
			.resources(URI.create("https://rs1.com"), URI.create("https://rs2.com"))
			.includeGrantedScopes(true)
			.build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(ResponseMode.FORM_POST, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals("https://c2id.com/login", request.getEndpointURI().toString());
		assertEquals("https://client.com/cb", request.getRedirectionURI().toString());
		assertEquals(new Scope("openid", "email"), request.getScope());
		assertEquals(new State("123"), request.getState());
		assertEquals(CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier), request.getCodeChallenge());
		assertEquals(CodeChallengeMethod.S256, request.getCodeChallengeMethod());
		assertEquals(Arrays.asList(URI.create("https://rs1.com"), URI.create("https://rs2.com")), request.getResources());
		assertTrue(request.includeGrantedScopes());
	}


	public void testBuilderFullAlt()
		throws Exception {

		CodeVerifier codeVerifier = new CodeVerifier();

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
			.endpointURI(new URI("https://c2id.com/login"))
			.redirectionURI(new URI("https://client.com/cb"))
			.scope(new Scope("openid", "email"))
			.state(new State("123"))
			.responseMode(ResponseMode.FORM_POST)
			.codeChallenge(codeVerifier, null)
			.resources(URI.create("https://rs1.com"))
			.includeGrantedScopes(false)
			.customParameter("x", "100")
			.customParameter("y", "200")
			.customParameter("z", "300")
			.build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(ResponseMode.FORM_POST, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals("https://c2id.com/login", request.getEndpointURI().toString());
		assertEquals("https://client.com/cb", request.getRedirectionURI().toString());
		assertEquals(new Scope("openid", "email"), request.getScope());
		assertEquals(new State("123"), request.getState());
		assertEquals(CodeChallenge.compute(CodeChallengeMethod.PLAIN, codeVerifier), request.getCodeChallenge());
		assertEquals(CodeChallengeMethod.PLAIN, request.getCodeChallengeMethod());
		assertEquals(Collections.singletonList(URI.create("https://rs1.com")), request.getResources());
		assertFalse(request.includeGrantedScopes());
		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameter("z"));
		assertEquals(Collections.singletonList("100"), request.getCustomParameters().get("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameters().get("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameters().get("z"));
		assertEquals(3, request.getCustomParameters().size());
	}


	public void testBuilderFull_codeChallengeDeprecated()
		throws Exception {

		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123")).
			endpointURI(new URI("https://c2id.com/login")).
			redirectionURI(new URI("https://client.com/cb")).
			scope(new Scope("openid", "email")).
			state(new State("123")).
			responseMode(ResponseMode.FORM_POST).
			codeChallenge(codeChallenge, CodeChallengeMethod.S256).
			build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(ResponseMode.FORM_POST, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals("https://c2id.com/login", request.getEndpointURI().toString());
		assertEquals("https://client.com/cb", request.getRedirectionURI().toString());
		assertEquals(new Scope("openid", "email"), request.getScope());
		assertEquals(new State("123"), request.getState());
		assertEquals(codeChallenge, request.getCodeChallenge());
		assertEquals(CodeChallengeMethod.S256, request.getCodeChallengeMethod());
	}


	public void testBuilderFullAlt_codeChallengeDeprecated()
		throws Exception {

		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.PLAIN, codeVerifier);


		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
			.endpointURI(new URI("https://c2id.com/login"))
			.redirectionURI(new URI("https://client.com/cb"))
			.scope(new Scope("openid", "email"))
			.state(new State("123"))
			.responseMode(ResponseMode.FORM_POST)
			.codeChallenge(codeChallenge, null)
			.customParameter("x", "100")
			.customParameter("y", "200")
			.customParameter("z", "300")
			.build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(ResponseMode.FORM_POST, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals("https://c2id.com/login", request.getEndpointURI().toString());
		assertEquals("https://client.com/cb", request.getRedirectionURI().toString());
		assertEquals(new Scope("openid", "email"), request.getScope());
		assertEquals(new State("123"), request.getState());
		assertEquals(codeChallenge, request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameter("z"));
		assertEquals(Collections.singletonList("100"), request.getCustomParameters().get("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameters().get("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameters().get("z"));
		assertEquals(3, request.getCustomParameters().size());
	}


	public void testParseExceptionMissingClientID()
		throws Exception {

		URI requestURI = new URI("https://server.example.com/authorize?" +
			"response_type=code" +
			"&state=xyz" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		try {
			AuthorizationRequest.parse(requestURI);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing \"client_id\" parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing \"client_id\" parameter", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseExceptionInvalidRedirectionURI()
		throws Exception {

		URI requestURI = new URI("https://server.example.com/authorize?" +
			"response_type=code" +
			"&client_id=s6BhdRkqt3" +
			"&state=xyz" +
			"&redirect_uri=%3A");

		try {
			AuthorizationRequest.parse(requestURI);
			fail();
		} catch (ParseException e) {
			assertTrue(e.getMessage().startsWith("Invalid \"redirect_uri\" parameter"));
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertTrue(e.getErrorObject().getDescription().startsWith("Invalid request: Invalid \"redirect_uri\" parameter"));
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseExceptionMissingResponseType()
		throws Exception {

		URI requestURI = new URI("https://server.example.com/authorize?" +
			"response_type=" +
			"&client_id=123" +
			"&state=xyz" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		try {
			AuthorizationRequest.parse(requestURI);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing \"response_type\" parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing \"response_type\" parameter", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}


	// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/147/authorizationrequestparse-final-uri-uri
	public void testParseWithEncodedEqualsChar()
		throws Exception {

		URI redirectURI = URI.create("https://client.com/in?app=123");

		String encodedRedirectURI = URLEncoder.encode(redirectURI.toString(), "UTF-8");

		URI requestURI = URI.create("https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=" +
			encodedRedirectURI);

		AuthorizationRequest request = AuthorizationRequest.parse(requestURI);

		assertEquals(ResponseType.parse("code"), request.getResponseType());
		assertEquals(new ClientID("s6BhdRkqt3"), request.getClientID());
		assertEquals(new State("xyz"), request.getState());
		assertEquals(redirectURI, request.getRedirectionURI());
	}
	
	
	public void testCopyConstructorBuilder()
		throws Exception {
		
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("apples", Collections.singletonList("10"));
		
		AuthorizationRequest in = new AuthorizationRequest(
			new URI("https://example.com/cb"),
			new ResponseType("code"),
			ResponseMode.FORM_POST,
			new ClientID("123"),
			new URI("https://example.com/cb"),
			new Scope("openid"),
			new State(),
			CodeChallenge.compute(CodeChallengeMethod.S256, new CodeVerifier()),
			CodeChallengeMethod.S256,
			Collections.singletonList(URI.create("https://rs1.com")),
			true,
			customParams);
		
		AuthorizationRequest out = new AuthorizationRequest.Builder(in).build();
		
		assertEquals(in.getResponseType(), out.getResponseType());
		assertEquals(in.getScope(), out.getScope());
		assertEquals(in.getClientID(), out.getClientID());
		assertEquals(in.getRedirectionURI(), out.getRedirectionURI());
		assertEquals(in.getState(), out.getState());
		assertEquals(in.getResponseMode(), out.getResponseMode());
		assertEquals(in.getCodeChallenge(), out.getCodeChallenge());
		assertEquals(in.getCodeChallengeMethod(), out.getCodeChallengeMethod());
		assertEquals(in.getResources(), out.getResources());
		assertEquals(in.includeGrantedScopes(), out.includeGrantedScopes());
		assertEquals(in.getCustomParameters(), out.getCustomParameters());
		assertEquals(in.getEndpointURI(), out.getEndpointURI());
	}
	
	
	public void testQueryParamsInEndpoint()
		throws Exception {
		
		URI endpoint = new URI("https://c2id.com/login?foo=bar");
		
		AuthorizationRequest request = new AuthorizationRequest(endpoint, new ResponseType(ResponseType.Value.CODE), new ClientID("123"));
		
		// query parameters belonging to the authz endpoint not included here
		Map<String,List<String>> requestParameters = request.toParameters();
		assertEquals(Collections.singletonList("code"), requestParameters.get("response_type"));
		assertEquals(Collections.singletonList("123"), requestParameters.get("client_id"));
		assertEquals(2, requestParameters.size());
		
		Map<String,List<String>> queryParams = URLUtils.parseParameters(request.toQueryString());
		assertEquals(Collections.singletonList("bar"), queryParams.get("foo"));
		assertEquals(Collections.singletonList("code"), queryParams.get("response_type"));
		assertEquals(Collections.singletonList("123"), queryParams.get("client_id"));
		assertEquals(3, queryParams.size());
		
		URI redirectToAS = request.toURI();
		
		Map<String,List<String>> finalParameters = URLUtils.parseParameters(redirectToAS.getQuery());
		assertEquals(Collections.singletonList("bar"), finalParameters.get("foo"));
		assertEquals(Collections.singletonList("code"), finalParameters.get("response_type"));
		assertEquals(Collections.singletonList("123"), finalParameters.get("client_id"));
		assertEquals(3, finalParameters.size());
	}
	
	
	public void testBuilderWithResource_rejectNonAbsoluteURI() {
		
		try {
			new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
				.resources(URI.create("https:///api/v1"))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Resource URI must be absolute and with no query or fragment: https:///api/v1", e.getMessage());
		}
	}
	
	
	public void testBuilderWithResource_rejectURIWithQuery() {
		
		try {
			new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
				.resources(URI.create("https://rs1.com/api/v1?query"))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Resource URI must be absolute and with no query or fragment: https://rs1.com/api/v1?query", e.getMessage());
		}
	}
	
	
	public void testBuilderWithResource_rejectURIWithFragment() {
		
		try {
			new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
				.resources(URI.create("https://rs1.com/api/v1#fragment"))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Resource URI must be absolute and with no query or fragment: https://rs1.com/api/v1#fragment", e.getMessage());
		}
	}
	
	
	public void testParseResourceIndicatorsExample()
		throws ParseException {
		
		AuthorizationRequest request = AuthorizationRequest.parse(
			URI.create(
				"https://authorization-server.example.com" +
				"/as/authorization.oauth2?response_type=token" +
				"&client_id=s6BhdRkqt3&state=laeb" +
				"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb" +
				"&resource=https%3A%2F%2Frs.example.com%2F"));
		
		assertEquals(new ClientID("s6BhdRkqt3"), request.getClientID());
		assertEquals(new State("laeb"), request.getState());
		assertEquals(new ResponseType("token"), request.getResponseType());
		assertEquals(URI.create("https://client.example.com/cb"), request.getRedirectionURI());
		assertEquals(Collections.singletonList(URI.create("https://rs.example.com/")), request.getResources());
	}
	
	
	public void testParse_rejectResourceURIWithHostNotAbsolute() {
		
		try {
			AuthorizationRequest.parse(URI.create("https://authorization-server.example.com" +
				"/as/authorization.oauth2?response_type=token" +
				"&client_id=s6BhdRkqt3&state=laeb" +
				"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb" +
				"&resource=https%3A%2F%2F%2F"));
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_RESOURCE, e.getErrorObject());
			assertEquals("Invalid \"resource\" parameter: Must be an absolute URI and with no query or fragment: https:///", e.getErrorObject().getDescription());
		}
	}
	
	
	public void testParse_rejectResourceURIWithQuery()
		throws UnsupportedEncodingException {
		
		try {
			AuthorizationRequest.parse(URI.create("https://authorization-server.example.com" +
				"/as/authorization.oauth2?response_type=token" +
				"&client_id=s6BhdRkqt3&state=laeb" +
				"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb" +
				"&resource=" + URLEncoder.encode("https://rs.example.com/?query", "utf-8")));
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_RESOURCE, e.getErrorObject());
			assertEquals("Invalid \"resource\" parameter: Must be an absolute URI and with no query or fragment: https://rs.example.com/?query", e.getErrorObject().getDescription());
		}
	}
	
	
	public void testParse_rejectResourceURIWithFragment()
		throws UnsupportedEncodingException {
		
		try {
			AuthorizationRequest.parse(URI.create("https://authorization-server.example.com" +
				"/as/authorization.oauth2?response_type=token" +
				"&client_id=s6BhdRkqt3&state=laeb" +
				"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb" +
				"&resource=" + URLEncoder.encode("https://rs.example.com/#fragment", "utf-8")));
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_RESOURCE, e.getErrorObject());
			assertEquals("Invalid \"resource\" parameter: Must be an absolute URI and with no query or fragment: https://rs.example.com/#fragment", e.getErrorObject().getDescription());
		}
	}
}
