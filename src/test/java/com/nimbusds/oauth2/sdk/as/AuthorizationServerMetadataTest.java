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

package com.nimbusds.oauth2.sdk.as;


import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;


public class AuthorizationServerMetadataTest extends TestCase {
	
	
	public void testRegisteredParameters() {
		
		Set<String> paramNames = AuthorizationServerMetadata.getRegisteredParameterNames();
		
		assertTrue(paramNames.contains("issuer"));
		assertTrue(paramNames.contains("authorization_endpoint"));
		assertTrue(paramNames.contains("token_endpoint"));
		assertTrue(paramNames.contains("jwks_uri"));
		assertTrue(paramNames.contains("registration_endpoint"));
		assertTrue(paramNames.contains("scopes_supported"));
		assertTrue(paramNames.contains("response_types_supported"));
		assertTrue(paramNames.contains("response_modes_supported"));
		assertTrue(paramNames.contains("grant_types_supported"));
		assertTrue(paramNames.contains("code_challenge_methods_supported"));
		assertTrue(paramNames.contains("request_object_endpoint"));
		assertTrue(paramNames.contains("request_parameter_supported"));
		assertTrue(paramNames.contains("require_request_uri_registration"));
		assertTrue(paramNames.contains("pushed_authorization_request_endpoint"));
		assertTrue(paramNames.contains("request_object_endpoint"));
		assertTrue(paramNames.contains("request_object_signing_alg_values_supported"));
		assertTrue(paramNames.contains("request_object_encryption_alg_values_supported"));
		assertTrue(paramNames.contains("request_object_encryption_enc_values_supported"));
		assertTrue(paramNames.contains("token_endpoint_auth_methods_supported"));
		assertTrue(paramNames.contains("token_endpoint_auth_signing_alg_values_supported"));
		assertTrue(paramNames.contains("service_documentation"));
		assertTrue(paramNames.contains("ui_locales_supported"));
		assertTrue(paramNames.contains("op_policy_uri"));
		assertTrue(paramNames.contains("op_tos_uri"));
		assertTrue(paramNames.contains("introspection_endpoint"));
		assertTrue(paramNames.contains("introspection_endpoint_auth_methods_supported"));
		assertTrue(paramNames.contains("introspection_endpoint_auth_signing_alg_values_supported"));
		assertTrue(paramNames.contains("revocation_endpoint"));
		assertTrue(paramNames.contains("revocation_endpoint_auth_methods_supported"));
		assertTrue(paramNames.contains("revocation_endpoint_auth_signing_alg_values_supported"));
		assertTrue(paramNames.contains("mtls_endpoint_aliases"));
		assertTrue(paramNames.contains("tls_client_certificate_bound_access_tokens"));
		assertTrue(paramNames.contains("authorization_signing_alg_values_supported"));
		assertTrue(paramNames.contains("authorization_encryption_alg_values_supported"));
		assertTrue(paramNames.contains("authorization_encryption_enc_values_supported"));
		assertTrue(paramNames.contains("device_authorization_endpoint"));
		
		assertEquals(36, paramNames.size());
	}
	
	
	public void testParseExample()
		throws Exception {
		
		String json = "{" +
			" \"issuer\":" +
			"   \"https://server.example.com\"," +
			" \"authorization_endpoint\":" +
			"   \"https://server.example.com/authorize\"," +
			" \"token_endpoint\":" +
			"   \"https://server.example.com/token\"," +
			" \"token_endpoint_auth_methods_supported\":" +
			"   [\"client_secret_basic\", \"private_key_jwt\"]," +
			" \"token_endpoint_auth_signing_alg_values_supported\":" +
			"   [\"RS256\", \"ES256\"]," +
			" \"userinfo_endpoint\":" +
			"   \"https://server.example.com/userinfo\"," +
			" \"jwks_uri\":" +
			"   \"https://server.example.com/jwks.json\"," +
			" \"registration_endpoint\":" +
			"   \"https://server.example.com/register\"," +
			" \"scopes_supported\":" +
			"   [\"openid\", \"profile\", \"email\", \"address\"," +
			"    \"phone\", \"offline_access\"]," +
			" \"response_types_supported\":" +
			"   [\"code\", \"code token\"]," +
			" \"service_documentation\":" +
			"   \"http://server.example.com/service_documentation.html\"," +
			" \"ui_locales_supported\":" +
			"   [\"en-US\", \"en-GB\", \"en-CA\", \"fr-FR\", \"fr-CA\"]" +
			"}";
		
		AuthorizationServerMetadata as = AuthorizationServerMetadata.parse(json);
		
		assertEquals(new Issuer("https://server.example.com"), as.getIssuer());
		assertEquals(new URI("https://server.example.com/authorize"), as.getAuthorizationEndpointURI());
		assertEquals(new URI("https://server.example.com/token"), as.getTokenEndpointURI());
		assertEquals(Arrays.asList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.PRIVATE_KEY_JWT), as.getTokenEndpointAuthMethods());
		assertEquals(new URI("https://server.example.com/userinfo"), as.getCustomURIParameter("userinfo_endpoint"));
		assertEquals(new URI("https://server.example.com/jwks.json"), as.getJWKSetURI());
		assertEquals(new URI("https://server.example.com/register"), as.getRegistrationEndpointURI());
		assertEquals(new Scope("openid", "profile", "email", "address", "phone", "offline_access"), as.getScopes());
		assertEquals(Arrays.asList(new ResponseType("code"), new ResponseType("code", "token")), as.getResponseTypes());
		assertEquals(new URI("http://server.example.com/service_documentation.html"), as.getServiceDocsURI());
		assertEquals(Arrays.asList(LangTag.parse("en-US"), LangTag.parse("en-GB"), LangTag.parse("en-CA"), LangTag.parse("fr-FR"), LangTag.parse("fr-CA")), as.getUILocales());
	}
	
	
	public void testApplyDefaults() {
		
		Issuer issuer = new Issuer("https://c2id.com");
		
		AuthorizationServerMetadata meta = new AuthorizationServerMetadata(issuer);
		
		meta.applyDefaults();
		
		List<ResponseMode> responseModes = meta.getResponseModes();
		assertTrue(responseModes.contains(ResponseMode.QUERY));
		assertTrue(responseModes.contains(ResponseMode.FRAGMENT));
		assertEquals(2, responseModes.size());
		
		List<GrantType> grantTypes = meta.getGrantTypes();
		assertTrue(grantTypes.contains(GrantType.AUTHORIZATION_CODE));
		assertTrue(grantTypes.contains(GrantType.IMPLICIT));
		assertEquals(2, grantTypes.size());
		
		assertEquals(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC), meta.getTokenEndpointAuthMethods());
	}
	
	
	public void testParseMinimal()
		throws Exception {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("issuer", "https://c2id.com");
		
		AuthorizationServerMetadata as = AuthorizationServerMetadata.parse(jsonObject.toJSONString());
		assertEquals(new Issuer("https://c2id.com"), as.getIssuer());
	}
	
	
	public void testParse_issuerNotURI() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("issuer", "a b c");
		
		try {
			AuthorizationServerMetadata.parse(jsonObject.toJSONString());
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal character in path at index 1: a b c", e.getMessage());
		}
	}
	
	
	public void testParse_issuerWithQuery() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("issuer", "https://c2id.com?a=b");
		
		try {
			AuthorizationServerMetadata.parse(jsonObject.toJSONString());
			fail();
		} catch (ParseException e) {
			assertEquals("The issuer URI must be without a query component", e.getMessage());
		}
	}
	
	
	public void testParse_issuerWithFragment() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("issuer", "https://c2id.com#abc");
		
		try {
			AuthorizationServerMetadata.parse(jsonObject.toJSONString());
			fail();
		} catch (ParseException e) {
			assertEquals("The issuer URI must be without a fragment component", e.getMessage());
		}
	}
	
	
	public void testRejectAlgNoneInEndpointJWSAlgs() {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		
		try {
			as.setTokenEndpointJWSAlgs(Collections.singletonList(new JWSAlgorithm("none")));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"none\" algorithm is not accepted", e.getMessage());
		}
		
		try {
			as.setIntrospectionEndpointJWSAlgs(Collections.singletonList(new JWSAlgorithm("none")));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"none\" algorithm is not accepted", e.getMessage());
		}
		
		try {
			as.setRevocationEndpointJWSAlgs(Collections.singletonList(new JWSAlgorithm("none")));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"none\" algorithm is not accepted", e.getMessage());
		}
	}
	
	
	public void testJARM() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		as.applyDefaults();
		
		assertNull(as.getAuthorizationJWSAlgs());
		assertNull(as.getAuthorizationJWEAlgs());
		assertNull(as.getAuthorizationJWEEncs());
		
		List<JWSAlgorithm> jwsAlgs = Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512);
		as.setAuthorizationJWSAlgs(jwsAlgs);
		assertEquals(jwsAlgs, as.getAuthorizationJWSAlgs());
		
		List<JWEAlgorithm> jweAlgs = Arrays.asList(JWEAlgorithm.ECDH_ES, JWEAlgorithm.ECDH_ES_A128KW);
		as.setAuthorizationJWEAlgs(jweAlgs);
		assertEquals(jweAlgs, as.getAuthorizationJWEAlgs());
		
		List<EncryptionMethod> jweEncs = Arrays.asList(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM);
		as.setAuthorizationJWEEncs(jweEncs);
		assertEquals(jweEncs, as.getAuthorizationJWEEncs());
		
		JSONObject jsonObject = as.toJSONObject();
		
		assertEquals(
			Arrays.asList(JWSAlgorithm.ES256.getName(), JWSAlgorithm.ES384.getName(), JWSAlgorithm.ES512.getName()),
			JSONObjectUtils.getStringList(jsonObject, "authorization_signing_alg_values_supported")
		);
		
		assertEquals(
			Arrays.asList(JWEAlgorithm.ECDH_ES.getName(), JWEAlgorithm.ECDH_ES_A128KW.getName()),
			JSONObjectUtils.getStringList(jsonObject, "authorization_encryption_alg_values_supported")
		);
		
		assertEquals(
			Arrays.asList(EncryptionMethod.A128GCM.getName(), EncryptionMethod.A256GCM.getName()),
			JSONObjectUtils.getStringList(jsonObject, "authorization_encryption_enc_values_supported")
		);
		
		as = AuthorizationServerMetadata.parse(jsonObject.toJSONString());
		
		assertEquals(jwsAlgs, as.getAuthorizationJWSAlgs());
		assertEquals(jweAlgs, as.getAuthorizationJWEAlgs());
		assertEquals(jweEncs, as.getAuthorizationJWEEncs());
	}
	
	
	public void testRequestObjectEndpoint() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		as.applyDefaults();
		assertNull(as.getRequestObjectEndpoint());
		
		JSONObject jsonObject = as.toJSONObject();
		assertFalse(jsonObject.containsKey("request_object_endpoint"));
		
		URI endpoint = URI.create("https://c2id.com/requests");
		
		as.setRequestObjectEndpoint(endpoint);
		
		assertEquals(endpoint, as.getRequestObjectEndpoint());
		
		jsonObject = as.toJSONObject();
		assertEquals(endpoint.toString(), jsonObject.get("request_object_endpoint"));
		
		as = AuthorizationServerMetadata.parse(jsonObject);
		
		assertEquals(endpoint, as.getRequestObjectEndpoint());
	}
	
	
	public void testRequestURIParamSupported_defaultFalse() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		assertFalse(as.supportsRequestURIParam());
		
		as.applyDefaults();
		assertFalse(as.supportsRequestURIParam());
		
		JSONObject jsonObject = as.toJSONObject();
		assertFalse(JSONObjectUtils.getBoolean(jsonObject, "request_uri_parameter_supported"));
	}
	
	
	public void testPAR() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		
		assertNull(as.getPushedAuthorizationRequestEndpointURI());
		
		as.applyDefaults();
		assertNull(as.getPushedAuthorizationRequestEndpointURI());
		
		URI parEndpoint = URI.create("https://c2id.com/par");
		as.setPushedAuthorizationRequestEndpointURI(parEndpoint);
		assertEquals(parEndpoint, as.getPushedAuthorizationRequestEndpointURI());
		
		JSONObject jsonObject = as.toJSONObject();
		assertEquals(parEndpoint.toString(), jsonObject.get("pushed_authorization_request_endpoint"));
		
		as = AuthorizationServerMetadata.parse(jsonObject.toJSONString());
		assertEquals(parEndpoint, as.getPushedAuthorizationRequestEndpointURI());
	}
}
