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


import java.util.Arrays;
import java.util.Date;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.auth.X509CertificateConfirmation;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


/**
 * Tests the token introspection success response class.
 */
public class TokenIntrospectionSuccessResponseTest extends TestCase {
	

	public void testExample()
		throws Exception {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setContentType("application/json");
		String json = 
			"{\n" +
			" \"active\": true,\n" +
			" \"client_id\": \"l238j323ds-23ij4\",\n" +
			" \"username\": \"jdoe\",\n" +
			" \"scope\": \"read write dolphin\",\n" +
			" \"sub\": \"Z5O3upPC88QrAjx00dis\",\n" +
			" \"aud\": \"https://protected.example.net/resource\",\n" +
			" \"iss\": \"https://server.example.com/\",\n" +
			" \"exp\": 1419356238,\n" +
			" \"iat\": 1419350238,\n" +
			" \"extension_field\": \"twenty-seven\"\n" +
			"}";
		httpResponse.setContent(json);

		TokenIntrospectionSuccessResponse response = TokenIntrospectionSuccessResponse.parse(httpResponse);
		assertTrue(response.indicatesSuccess());
		assertTrue(response.isActive());
		assertEquals(new ClientID("l238j323ds-23ij4"), response.getClientID());
		assertEquals("jdoe", response.getUsername());
		assertEquals(Scope.parse("read write dolphin"), response.getScope());
		assertEquals(new Subject("Z5O3upPC88QrAjx00dis"), response.getSubject());
		assertEquals(new Audience("https://protected.example.net/resource"), response.getAudience().get(0));
		assertEquals(1, response.getAudience().size());
		assertEquals(new Issuer("https://server.example.com/"), response.getIssuer());
		assertEquals(DateUtils.fromSecondsSinceEpoch(1419356238L), response.getExpirationTime());
		assertEquals(DateUtils.fromSecondsSinceEpoch(1419350238L), response.getIssueTime());
		assertNull(response.getX509CertificateSHA256Thumbprint());
		assertNull(response.getX509CertificateConfirmation());
		assertEquals("twenty-seven", response.toJSONObject().get("extension_field"));

		httpResponse = response.toHTTPResponse();

		response = TokenIntrospectionSuccessResponse.parse(httpResponse);
		assertTrue(response.indicatesSuccess());
		assertTrue(response.isActive());
		assertEquals(new ClientID("l238j323ds-23ij4"), response.getClientID());
		assertEquals("jdoe", response.getUsername());
		assertEquals(Scope.parse("read write dolphin"), response.getScope());
		assertEquals(new Subject("Z5O3upPC88QrAjx00dis"), response.getSubject());
		assertEquals(new Audience("https://protected.example.net/resource"), response.getAudience().get(0));
		assertEquals(1, response.getAudience().size());
		assertEquals(new Issuer("https://server.example.com/"), response.getIssuer());
		assertEquals(DateUtils.fromSecondsSinceEpoch(1419356238L), response.getExpirationTime());
		assertEquals(DateUtils.fromSecondsSinceEpoch(1419350238L), response.getIssueTime());
		assertNull(response.getX509CertificateSHA256Thumbprint());
		assertNull(response.getX509CertificateConfirmation());
		assertEquals("twenty-seven", response.toJSONObject().get("extension_field"));
	}


	public void testBuilderMinimal_active()
		throws Exception {

		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
			.build();

		assertTrue(response.isActive());
		assertNull(response.getScope());
		assertNull(response.getClientID());
		assertNull(response.getUsername());
		assertNull(response.getTokenType());
		assertNull(response.getExpirationTime());
		assertNull(response.getIssueTime());
		assertNull(response.getNotBeforeTime());
		assertNull(response.getSubject());
		assertNull(response.getAudience());
		assertNull(response.getIssuer());
		assertNull(response.getJWTID());
		assertNull(response.getX509CertificateSHA256Thumbprint());
		assertNull(response.getX509CertificateConfirmation());

		JSONObject jsonObject = response.toJSONObject();
		assertTrue((Boolean) jsonObject.get("active"));
		assertEquals(1, jsonObject.size());

		HTTPResponse httpResponse = response.toHTTPResponse();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals(ContentType.APPLICATION_JSON.getBaseType(), httpResponse.getEntityContentType().getBaseType());
		jsonObject = httpResponse.getContentAsJSONObject();
		assertTrue((Boolean) jsonObject.get("active"));
		assertEquals(1, jsonObject.size());

		response = TokenIntrospectionSuccessResponse.parse(httpResponse);

		assertTrue(response.isActive());
		assertNull(response.getScope());
		assertNull(response.getClientID());
		assertNull(response.getUsername());
		assertNull(response.getTokenType());
		assertNull(response.getExpirationTime());
		assertNull(response.getIssueTime());
		assertNull(response.getNotBeforeTime());
		assertNull(response.getSubject());
		assertNull(response.getAudience());
		assertNull(response.getIssuer());
		assertNull(response.getJWTID());
		assertNull(response.getX509CertificateSHA256Thumbprint());
		assertNull(response.getX509CertificateConfirmation());
	}


	public void testBuilderMinimal_inactive()
		throws Exception {

		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(false)
			.build();

		assertFalse(response.isActive());
		assertNull(response.getScope());
		assertNull(response.getClientID());
		assertNull(response.getUsername());
		assertNull(response.getTokenType());
		assertNull(response.getExpirationTime());
		assertNull(response.getIssueTime());
		assertNull(response.getNotBeforeTime());
		assertNull(response.getSubject());
		assertNull(response.getAudience());
		assertNull(response.getIssuer());
		assertNull(response.getJWTID());
		assertNull(response.getX509CertificateSHA256Thumbprint());
		assertNull(response.getX509CertificateConfirmation());

		JSONObject jsonObject = response.toJSONObject();
		assertFalse((Boolean) jsonObject.get("active"));
		assertEquals(1, jsonObject.size());

		HTTPResponse httpResponse = response.toHTTPResponse();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals(ContentType.APPLICATION_JSON.getBaseType(), httpResponse.getEntityContentType().getBaseType());
		jsonObject = httpResponse.getContentAsJSONObject();
		assertFalse((Boolean) jsonObject.get("active"));
		assertEquals(1, jsonObject.size());

		response = TokenIntrospectionSuccessResponse.parse(httpResponse);

		assertFalse(response.isActive());
		assertNull(response.getScope());
		assertNull(response.getClientID());
		assertNull(response.getUsername());
		assertNull(response.getTokenType());
		assertNull(response.getExpirationTime());
		assertNull(response.getIssueTime());
		assertNull(response.getNotBeforeTime());
		assertNull(response.getSubject());
		assertNull(response.getAudience());
		assertNull(response.getIssuer());
		assertNull(response.getJWTID());
		assertNull(response.getScope());
		assertNull(response.getClientID());
		assertNull(response.getUsername());
		assertNull(response.getTokenType());
		assertNull(response.getExpirationTime());
		assertNull(response.getIssueTime());
		assertNull(response.getNotBeforeTime());
		assertNull(response.getSubject());
		assertNull(response.getAudience());
		assertNull(response.getIssuer());
		assertNull(response.getJWTID());
		assertNull(response.getX509CertificateSHA256Thumbprint());
		assertNull(response.getX509CertificateConfirmation());
	}


	public void testBuilder_complete()
		throws Exception {

		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
			.scope(Scope.parse("read write"))
			.clientID(new ClientID("123"))
			.username("alice")
			.tokenType(AccessTokenType.BEARER)
			.expirationTime(DateUtils.fromSecondsSinceEpoch(102030L))
			.issueTime(DateUtils.fromSecondsSinceEpoch(203040L))
			.notBeforeTime(DateUtils.fromSecondsSinceEpoch(304050L))
			.subject(new Subject("alice.wonderland"))
			.audience(Audience.create("456", "789"))
			.issuer(new Issuer("https://c2id.com"))
			.jwtID(new JWTID("xyz"))
			.x509CertificateConfirmation(new X509CertificateConfirmation(new Base64URL("abc")))
			.parameter("ip", "10.20.30.40")
			.build();

		assertTrue(response.isActive());
		assertEquals(Scope.parse("read write"), response.getScope());
		assertEquals(new ClientID("123"), response.getClientID());
		assertEquals("alice", response.getUsername());
		assertEquals(AccessTokenType.BEARER, response.getTokenType());
		assertEquals(DateUtils.fromSecondsSinceEpoch(102030L), response.getExpirationTime());
		assertEquals(DateUtils.fromSecondsSinceEpoch(203040L), response.getIssueTime());
		assertEquals(DateUtils.fromSecondsSinceEpoch(304050L), response.getNotBeforeTime());
		assertEquals(new Subject("alice.wonderland"), response.getSubject());
		assertEquals(Audience.create("456", "789"), response.getAudience());
		assertEquals(new Issuer("https://c2id.com"), response.getIssuer());
		assertEquals(new JWTID("xyz"), response.getJWTID());
		assertEquals(new Base64URL("abc"), response.getX509CertificateConfirmation().getValue());
		assertEquals("10.20.30.40", response.toJSONObject().get("ip"));

		assertEquals(14, response.toJSONObject().size());

		HTTPResponse httpResponse = response.toHTTPResponse();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("application/json; charset=UTF-8", httpResponse.getEntityContentType().toString());

		response = TokenIntrospectionSuccessResponse.parse(httpResponse);

		assertTrue(response.isActive());
		assertEquals(Scope.parse("read write"), response.getScope());
		assertEquals(new ClientID("123"), response.getClientID());
		assertEquals("alice", response.getUsername());
		assertEquals(AccessTokenType.BEARER, response.getTokenType());
		assertEquals(DateUtils.fromSecondsSinceEpoch(102030L), response.getExpirationTime());
		assertEquals(DateUtils.fromSecondsSinceEpoch(203040L), response.getIssueTime());
		assertEquals(DateUtils.fromSecondsSinceEpoch(304050L), response.getNotBeforeTime());
		assertEquals(new Subject("alice.wonderland"), response.getSubject());
		assertEquals(Audience.create("456", "789"), response.getAudience());
		assertEquals(new Issuer("https://c2id.com"), response.getIssuer());
		assertEquals(new JWTID("xyz"), response.getJWTID());
		assertEquals(new Base64URL("abc"), response.getX509CertificateConfirmation().getValue());
		assertEquals("10.20.30.40", response.toJSONObject().get("ip"));

		assertEquals(14, response.toJSONObject().size());
	}


	public void testBuilder_deprecatedCnfX5t()
		throws Exception {

		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
			.scope(Scope.parse("read write"))
			.x509CertificateSHA256Thumbprint(new Base64URL("abc"))
			.build();

		assertTrue(response.isActive());
		assertEquals(Scope.parse("read write"), response.getScope());
		assertEquals(new Base64URL("abc"), response.getX509CertificateSHA256Thumbprint());

		assertEquals(3, response.toJSONObject().size());

		HTTPResponse httpResponse = response.toHTTPResponse();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("application/json; charset=UTF-8", httpResponse.getEntityContentType().toString());

		response = TokenIntrospectionSuccessResponse.parse(httpResponse);
		
		assertTrue(response.isActive());
		assertEquals(Scope.parse("read write"), response.getScope());
		assertEquals(new Base64URL("abc"), response.getX509CertificateSHA256Thumbprint());

		assertEquals(3, response.toJSONObject().size());
	}
	
	
	public void testMutualTLSExample()
		throws Exception {
		
		String json = "{" +
			"  \"active\": true," +
			"  \"iss\": \"https://server.example.com\"," +
			"  \"sub\": \"ty.webb@example.com\"," +
			"  \"exp\": 1493726400," +
			"  \"nbf\": 1493722800," +
			"  \"cnf\":{" +
			"    \"x5t#S256\": \"bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2\"" +
			"  }" +
			"}";
		
		JSONObject jsonObject = JSONObjectUtils.parse(json);
		
		TokenIntrospectionSuccessResponse response = TokenIntrospectionSuccessResponse.parse(jsonObject);
		assertTrue(response.isActive());
		assertEquals(new Issuer("https://server.example.com"), response.getIssuer());
		assertEquals(new Subject("ty.webb@example.com"), response.getSubject());
		assertEquals(new Date(1493726400*1000L), response.getExpirationTime());
		assertEquals(new Date(1493722800*1000L), response.getNotBeforeTime());
		assertEquals(new Base64URL("bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"), response.getX509CertificateConfirmation().getValue());
		assertEquals(new Base64URL("bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"), response.getX509CertificateSHA256Thumbprint());
	}
	
	
	public void testCopyConstructorBuilder() {
		
		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
			.issuer(new Issuer("https://c2id.com"))
			.subject(new Subject("alice"))
			.scope(new Scope("openid", "email"))
			.build();
		
		TokenIntrospectionSuccessResponse copy = new TokenIntrospectionSuccessResponse.Builder(response)
			.build();
		
		assertEquals(response.isActive(), copy.isActive());
		assertEquals(response.getIssuer(), copy.getIssuer());
		assertEquals(response.getSubject(), copy.getSubject());
		assertEquals(response.getScope(), copy.getScope());
		
		assertEquals(response.toJSONObject(), copy.toJSONObject());
	}
	
	
	public void testGetParameters() throws ParseException {
		
		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
			.issuer(new Issuer("https://c2id.com"))
			.subject(new Subject("alice"))
			.scope(new Scope("openid", "email"))
			.build();
		
		JSONObject parameters = response.getParameters();
		assertEquals(true, JSONObjectUtils.getBoolean(parameters, "active"));
		assertEquals(response.getIssuer().getValue(), JSONObjectUtils.getString(parameters, "iss"));
		assertEquals(response.getSubject().getValue(), JSONObjectUtils.getString(parameters, "sub"));
		assertEquals(response.getScope().toString(), JSONObjectUtils.getString(parameters, "scope"));
		assertEquals(4, parameters.size());
		
		// modify subject
		parameters.put("sub", "bob");
		
		// change reflected in response object
		assertEquals(new Subject("bob"), response.getSubject());
	}
	
	
	public void testGetStringParameter() {
		
		Date iat = new Date();
		
		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
			.issuer(new Issuer("https://c2id.com"))
			.issueTime(iat)
			.subject(new Subject("alice"))
			.scope(new Scope("openid", "email"))
			.build();
		
		assertEquals("alice", response.getStringParameter("sub"));
		assertNull(response.getStringParameter("iat")); // not string
	}
	
	
	public void testGetBooleanParameter()
		throws ParseException {
		
		Date iat = new Date();
		
		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
			.issuer(new Issuer("https://c2id.com"))
			.issueTime(iat)
			.subject(new Subject("alice"))
			.scope(new Scope("openid", "email"))
			.build();
		
		assertTrue(response.getBooleanParameter("active"));
		try {
			response.getBooleanParameter("iat");
		} catch (ParseException e) {
			assertEquals("Unexpected type of JSON object member with key \"iat\"", e.getMessage());
		}
	}
	
	
	public void testGetNumberParameter() {
		
		Date iat = new Date(new Date().getTime() / 1000 * 1000);
		
		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
			.issuer(new Issuer("https://c2id.com"))
			.issueTime(iat)
			.subject(new Subject("alice"))
			.scope(new Scope("openid", "email"))
			.build();
		
		assertEquals(iat.getTime() / 1000L, response.getNumberParameter("iat").longValue());
		
		assertNull(response.getNumberParameter("sub")); // invalid number
	}
	
	
	public void testGetStringListParameter() {
		
		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
			.issuer(new Issuer("https://c2id.com"))
			.subject(new Subject("alice"))
			.scope(new Scope("openid", "email"))
			.parameter("claims", Arrays.asList("email", "email_verified"))
			.build();
		
		assertEquals(Arrays.asList("email", "email_verified"), response.getStringListParameter("claims"));
		
		assertNull(response.getStringListParameter("sub")); // invalid string list
	}
	
	
	public void testGetJSONObjectParameter() {
		
		JSONObject data = new JSONObject();
		data.put("ip", "192.168.0.1");
		
		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
			.issuer(new Issuer("https://c2id.com"))
			.subject(new Subject("alice"))
			.scope(new Scope("openid", "email"))
			.parameter("data", data)
			.build();
		
		assertEquals(data, response.getJSONObjectParameter("data"));
		
		assertNull(response.getJSONObjectParameter("sub")); // invalid parameter
	}
}
