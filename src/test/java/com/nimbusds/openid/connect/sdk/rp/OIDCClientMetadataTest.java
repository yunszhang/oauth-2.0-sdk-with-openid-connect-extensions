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

package com.nimbusds.openid.connect.sdk.rp;


import java.net.URI;
import java.net.URL;
import java.util.*;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.client.RegistrationError;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.id.SectorID;


public class OIDCClientMetadataTest extends TestCase {


	public void testRegisteredParameters() {

		Set<String> paramNames = OIDCClientMetadata.getRegisteredParameterNames();

		// Base OAuth 2.0 params
		assertTrue(paramNames.contains("redirect_uris"));
		assertTrue(paramNames.contains("client_name"));
		assertTrue(paramNames.contains("client_uri"));
		assertTrue(paramNames.contains("logo_uri"));
		assertTrue(paramNames.contains("contacts"));
		assertTrue(paramNames.contains("tos_uri"));
		assertTrue(paramNames.contains("policy_uri"));
		assertTrue(paramNames.contains("token_endpoint_auth_method"));
		assertTrue(paramNames.contains("token_endpoint_auth_signing_alg"));
		assertTrue(paramNames.contains("scope"));
		assertTrue(paramNames.contains("grant_types"));
		assertTrue(paramNames.contains("response_types"));
		assertTrue(paramNames.contains("jwks_uri"));
		assertTrue(paramNames.contains("jwks"));
		assertTrue(paramNames.contains("request_uris"));
		assertTrue(paramNames.contains("request_object_signing_alg"));
		assertTrue(paramNames.contains("request_object_encryption_alg"));
		assertTrue(paramNames.contains("request_object_encryption_enc"));
		assertTrue(paramNames.contains("software_id"));
		assertTrue(paramNames.contains("software_version"));
		assertTrue(paramNames.contains("tls_client_certificate_bound_access_tokens"));
		assertTrue(paramNames.contains("tls_client_auth_subject_dn"));
		assertTrue(paramNames.contains("tls_client_auth_san_dns"));
		assertTrue(paramNames.contains("tls_client_auth_san_uri"));
		assertTrue(paramNames.contains("tls_client_auth_san_ip"));
		assertTrue(paramNames.contains("tls_client_auth_san_email"));
		assertTrue(paramNames.contains("authorization_signed_response_alg"));
		assertTrue(paramNames.contains("authorization_encrypted_response_enc"));
		assertTrue(paramNames.contains("authorization_encrypted_response_enc"));

		// OIDC specifid params
		assertTrue(paramNames.contains("application_type"));
		assertTrue(paramNames.contains("sector_identifier_uri"));
		assertTrue(paramNames.contains("subject_type"));
		assertTrue(paramNames.contains("id_token_signed_response_alg"));
		assertTrue(paramNames.contains("id_token_encrypted_response_alg"));
		assertTrue(paramNames.contains("id_token_encrypted_response_enc"));
		assertTrue(paramNames.contains("userinfo_signed_response_alg"));
		assertTrue(paramNames.contains("userinfo_encrypted_response_alg"));
		assertTrue(paramNames.contains("userinfo_encrypted_response_enc"));
		assertTrue(paramNames.contains("default_max_age"));
		assertTrue(paramNames.contains("require_auth_time"));
		assertTrue(paramNames.contains("default_acr_values"));
		assertTrue(paramNames.contains("initiate_login_uri"));
		assertTrue(paramNames.contains("post_logout_redirect_uris"));
		assertTrue(paramNames.contains("frontchannel_logout_uri"));
		assertTrue(paramNames.contains("frontchannel_logout_session_required"));
		assertTrue(paramNames.contains("backchannel_logout_uri"));
		assertTrue(paramNames.contains("backchannel_logout_session_required"));
		assertTrue(paramNames.contains("federation_type"));
		assertTrue(paramNames.contains("organization_name"));
		assertTrue(paramNames.contains("trust_anchor_id"));

		assertEquals(50, OIDCClientMetadata.getRegisteredParameterNames().size());
	}
	
	
	public void testParseSpecExample()
		throws Exception {
		
		String jsonString = "{"
			+ "   \"application_type\": \"web\","
			+ "   \"redirect_uris\":[\"https://client.example.org/callback\",\"https://client.example.org/callback2\"],"
			+ "   \"client_name\": \"My Example\","
			+ "   \"client_name#ja-Jpan-JP\":\"クライアント名\","
			+ "   \"logo_uri\": \"https://client.example.org/logo.png\","
			+ "   \"subject_type\": \"pairwise\","
			+ "   \"sector_identifier_uri\":\"https://other.example.net/file_of_redirect_uris.json\","
			+ "   \"token_endpoint_auth_method\": \"client_secret_basic\","
			+ "   \"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\","
			+ "   \"userinfo_encrypted_response_alg\": \"RSA1_5\","
			+ "   \"userinfo_encrypted_response_enc\": \"A128CBC-HS256\","
			+ "   \"contacts\": [\"ve7jtb@example.org\", \"mary@example.org\"],"
			+ "   \"request_uris\":[\"https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA\"]"
			+ "  }";

		
		JSONObject jsonObject = JSONObjectUtils.parse(jsonString);
		
		OIDCClientMetadata clientMetadata = OIDCClientMetadata.parse(jsonObject);
		
		assertEquals(ApplicationType.WEB, clientMetadata.getApplicationType());
		
		Set<URI> redirectURIs = clientMetadata.getRedirectionURIs();
		
		assertTrue(redirectURIs.contains(new URI("https://client.example.org/callback")));
		assertTrue(redirectURIs.contains(new URI("https://client.example.org/callback2")));
		assertEquals(2, redirectURIs.size());
		
		assertEquals("My Example", clientMetadata.getName());
		assertEquals("クライアント名", clientMetadata.getName(LangTag.parse("ja-Jpan-JP")));

		assertEquals(new URL("https://client.example.org/logo.png").toString(), clientMetadata.getLogoURI().toString());
		
		assertEquals(SubjectType.PAIRWISE, clientMetadata.getSubjectType());
		
		assertEquals(new URL("https://other.example.net/file_of_redirect_uris.json").toString(), clientMetadata.getSectorIDURI().toString());
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, clientMetadata.getTokenEndpointAuthMethod());
		
		assertEquals(new URL("https://client.example.org/my_public_keys.jwks").toString(), clientMetadata.getJWKSetURI().toString());
		
		assertEquals(JWEAlgorithm.RSA1_5, clientMetadata.getUserInfoJWEAlg());
		assertEquals(EncryptionMethod.A128CBC_HS256, clientMetadata.getUserInfoJWEEnc());
		
		Set<URI> requestURIs = clientMetadata.getRequestObjectURIs();
		
		assertTrue(requestURIs.contains(new URI("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA")));
		assertEquals(1, requestURIs.size());
		
		assertNull(clientMetadata.getFrontChannelLogoutURI());
		assertFalse(clientMetadata.requiresFrontChannelLogoutSession());
		assertNull(clientMetadata.getBackChannelLogoutURI());
		assertFalse(clientMetadata.requiresBackChannelLogoutSession());

		assertTrue(clientMetadata.getCustomFields().isEmpty());
	}


	public void testGettersAndSetters()
		throws Exception {

		OIDCClientMetadata meta = new OIDCClientMetadata();

		assertNull(meta.getApplicationType());
		meta.setApplicationType(ApplicationType.NATIVE);
		assertEquals(ApplicationType.NATIVE, meta.getApplicationType());

		assertNull(meta.getSubjectType());
		meta.setSubjectType(SubjectType.PAIRWISE);
		assertEquals(SubjectType.PAIRWISE, meta.getSubjectType());

		assertNull(meta.getSectorIDURI());
		URI sectorIDURI = new URI("https://example.com/callbacks.json");
		meta.setSectorIDURI(sectorIDURI);
		assertEquals(sectorIDURI.toString(), meta.getSectorIDURI().toString());

		assertNull(meta.getRequestObjectURIs());
		Set<URI> requestObjURIs = new HashSet<>();
		requestObjURIs.add(new URI("http://client.com/reqobj"));
		meta.setRequestObjectURIs(requestObjURIs);
		assertEquals("http://client.com/reqobj", meta.getRequestObjectURIs().iterator().next().toString());
		assertEquals(1, meta.getRequestObjectURIs().size());

		assertNull(meta.getRequestObjectJWSAlg());
		meta.setRequestObjectJWSAlg(JWSAlgorithm.HS512);
		assertEquals(JWSAlgorithm.HS512, meta.getRequestObjectJWSAlg());

		assertNull(meta.getRequestObjectJWEAlg());
		meta.setRequestObjectJWEAlg(JWEAlgorithm.A128KW);
		assertEquals(JWEAlgorithm.A128KW, meta.getRequestObjectJWEAlg());

		assertNull(meta.getRequestObjectJWEEnc());
		meta.setRequestObjectJWEEnc(EncryptionMethod.A128GCM);
		assertEquals(EncryptionMethod.A128GCM, meta.getRequestObjectJWEEnc());

		assertNull(meta.getTokenEndpointAuthJWSAlg());
		meta.setTokenEndpointAuthJWSAlg(JWSAlgorithm.HS384);
		assertEquals(JWSAlgorithm.HS384, meta.getTokenEndpointAuthJWSAlg());

		assertNull(meta.getIDTokenJWSAlg());
		meta.setIDTokenJWSAlg(JWSAlgorithm.PS256);
		assertEquals(JWSAlgorithm.PS256, meta.getIDTokenJWSAlg());

		assertNull(meta.getIDTokenJWEAlg());
		meta.setIDTokenJWEAlg(JWEAlgorithm.A128KW);
		assertEquals(JWEAlgorithm.A128KW, meta.getIDTokenJWEAlg());

		assertNull(meta.getIDTokenJWEEnc());
		meta.setIDTokenJWEEnc(EncryptionMethod.A128GCM);
		assertEquals(EncryptionMethod.A128GCM, meta.getIDTokenJWEEnc());

		assertNull(meta.getUserInfoJWSAlg());
		meta.setUserInfoJWSAlg(JWSAlgorithm.ES256);
		assertEquals(JWSAlgorithm.ES256, meta.getUserInfoJWSAlg());

		assertNull(meta.getUserInfoJWEAlg());
		meta.setUserInfoJWEAlg(JWEAlgorithm.ECDH_ES);
		assertEquals(JWEAlgorithm.ECDH_ES, meta.getUserInfoJWEAlg());

		assertNull(meta.getUserInfoJWEEnc());
		meta.setUserInfoJWEEnc(EncryptionMethod.A128CBC_HS256);
		assertEquals(EncryptionMethod.A128CBC_HS256, meta.getUserInfoJWEEnc());

		assertEquals(-1, meta.getDefaultMaxAge());
		meta.setDefaultMaxAge(3600);
		assertEquals(3600, meta.getDefaultMaxAge());

		assertFalse(meta.requiresAuthTime());
		meta.requiresAuthTime(true);
		assertTrue(meta.requiresAuthTime());

		assertNull(meta.getDefaultACRs());
		List<ACR> acrList = new LinkedList<>();
		acrList.add(new ACR("1"));
		meta.setDefaultACRs(acrList);
		assertEquals("1", meta.getDefaultACRs().get(0).toString());

		assertNull(meta.getInitiateLoginURI());
		meta.setInitiateLoginURI(new URI("http://do-login.com"));
		assertEquals("http://do-login.com", meta.getInitiateLoginURI().toString());

		assertNull(meta.getPostLogoutRedirectionURIs());
		Set<URI> logoutURIs = new HashSet<>();
		logoutURIs.add(new URI("http://post-logout.com"));
		meta.setPostLogoutRedirectionURIs(logoutURIs);
		assertEquals("http://post-logout.com", meta.getPostLogoutRedirectionURIs().iterator().next().toString());
		
		assertNull(meta.getFrontChannelLogoutURI());
		meta.setFrontChannelLogoutURI(URI.create("https://example.com/logout/front-channel"));
		assertEquals(URI.create("https://example.com/logout/front-channel"), meta.getFrontChannelLogoutURI());
		
		assertFalse(meta.requiresFrontChannelLogoutSession());
		meta.requiresFrontChannelLogoutSession(true);
		assertTrue(meta.requiresFrontChannelLogoutSession());
		
		assertNull(meta.getBackChannelLogoutURI());
		meta.setBackChannelLogoutURI(URI.create("https://example.com/logout/back-channel"));
		assertEquals(URI.create("https://example.com/logout/back-channel"), meta.getBackChannelLogoutURI());
		
		assertFalse(meta.requiresBackChannelLogoutSession());
		meta.requiresBackChannelLogoutSession(true);
		assertTrue(meta.requiresBackChannelLogoutSession());

		String json = meta.toJSONObject().toJSONString();

		meta = OIDCClientMetadata.parse(JSONObjectUtils.parse(json));

		assertEquals(ApplicationType.NATIVE, meta.getApplicationType());

		assertEquals(SubjectType.PAIRWISE, meta.getSubjectType());

		assertEquals(sectorIDURI.toString(), meta.getSectorIDURI().toString());

		assertEquals("http://client.com/reqobj", meta.getRequestObjectURIs().iterator().next().toString());
		assertEquals(1, meta.getRequestObjectURIs().size());

		assertEquals(JWSAlgorithm.HS512, meta.getRequestObjectJWSAlg());
		assertEquals(JWEAlgorithm.A128KW, meta.getRequestObjectJWEAlg());
		assertEquals(EncryptionMethod.A128GCM, meta.getRequestObjectJWEEnc());

		assertEquals(JWSAlgorithm.HS384, meta.getTokenEndpointAuthJWSAlg());
		assertEquals(JWSAlgorithm.PS256, meta.getIDTokenJWSAlg());
		assertEquals(JWEAlgorithm.A128KW, meta.getIDTokenJWEAlg());
		assertEquals(EncryptionMethod.A128GCM, meta.getIDTokenJWEEnc());

		assertEquals(JWSAlgorithm.ES256, meta.getUserInfoJWSAlg());
		assertEquals(JWEAlgorithm.ECDH_ES, meta.getUserInfoJWEAlg());
		assertEquals(EncryptionMethod.A128CBC_HS256, meta.getUserInfoJWEEnc());

		assertEquals(3600, meta.getDefaultMaxAge());

		assertTrue(meta.requiresAuthTime());

		assertEquals("1", meta.getDefaultACRs().get(0).toString());

		assertEquals("http://do-login.com", meta.getInitiateLoginURI().toString());

		assertEquals("http://post-logout.com", meta.getPostLogoutRedirectionURIs().iterator().next().toString());
		
		assertEquals(URI.create("https://example.com/logout/front-channel"), meta.getFrontChannelLogoutURI());
		assertTrue(meta.requiresFrontChannelLogoutSession());
		
		assertEquals(URI.create("https://example.com/logout/back-channel"), meta.getBackChannelLogoutURI());
		assertTrue(meta.requiresBackChannelLogoutSession());
	}


	public void testCustomFields()
		throws Exception {

		OIDCClientMetadata meta = new OIDCClientMetadata();

		meta.setCustomField("x-data", "123");

		assertEquals("123", (String)meta.getCustomField("x-data"));
		assertEquals("123", (String)meta.getCustomFields().get("x-data"));
		assertEquals(1, meta.getCustomFields().size());

		String json = meta.toJSONObject().toJSONString();

		meta = OIDCClientMetadata.parse(JSONObjectUtils.parse(json));

		assertEquals("123", (String)meta.getCustomField("x-data"));
		assertEquals("123", (String)meta.getCustomFields().get("x-data"));
		assertEquals(1, meta.getCustomFields().size());
	}


	public void testApplyDefaults() throws ParseException {

		OIDCClientMetadata metadata = new OIDCClientMetadata();

		assertNull(metadata.getResponseTypes());
		assertNull(metadata.getGrantTypes());
		assertNull(metadata.getTokenEndpointAuthMethod());
		assertNull(metadata.getIDTokenJWSAlg());
		assertNull(metadata.getApplicationType());

		metadata.applyDefaults();

		assertTrue(metadata.getResponseTypes().contains(ResponseType.getDefault()));
		assertTrue(metadata.getResponseTypes().contains(new ResponseType(ResponseType.Value.CODE)));
		assertEquals(1, metadata.getResponseTypes().size());

		assertTrue(metadata.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE));
		assertEquals(1, metadata.getGrantTypes().size());

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, metadata.getTokenEndpointAuthMethod());

		assertEquals(JWSAlgorithm.RS256, metadata.getIDTokenJWSAlg());

		assertEquals(ApplicationType.WEB, metadata.getApplicationType());
		
		JSONObject jsonObject = metadata.toJSONObject();
		
		assertEquals(Collections.singletonList("authorization_code"), JSONObjectUtils.getStringList(jsonObject, "grant_types"));
		assertEquals(Collections.singletonList("code"), JSONObjectUtils.getStringList(jsonObject, "response_types"));
		assertEquals(ApplicationType.WEB.toString(), jsonObject.get("application_type"));
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue(), jsonObject.get("token_endpoint_auth_method"));
		assertEquals(JWSAlgorithm.RS256.getName(), jsonObject.get("id_token_signed_response_alg"));
		assertEquals(5, jsonObject.size());
	}
	
	
	public void testApplyDefaults_JARM_implicitJWEEnc()
		throws Exception {
		
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setAuthorizationJWEAlg(JWEAlgorithm.ECDH_ES);
		
		metadata.applyDefaults();
		
		Set<ResponseType> rts = metadata.getResponseTypes();
		assertTrue(rts.contains(ResponseType.parse("code")));
		
		Set<GrantType> grantTypes = metadata.getGrantTypes();
		assertTrue(grantTypes.contains(GrantType.AUTHORIZATION_CODE));
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, metadata.getTokenEndpointAuthMethod());
		
		// JARM
		assertNull(metadata.getAuthorizationJWSAlg());
		assertEquals(JWEAlgorithm.ECDH_ES, metadata.getAuthorizationJWEAlg());
		assertEquals(EncryptionMethod.A128CBC_HS256, metadata.getAuthorizationJWEEnc());
	}


	public void testSerialiseDefaultRequireAuthTime() {

		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.applyDefaults();

		JSONObject jsonObject = metadata.toJSONObject();

		assertNull(jsonObject.get("require_auth_time"));
	}


	public void testSerialiseNonDefaultRequireAuthTime() {

		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.requiresAuthTime(true);
		metadata.applyDefaults();

		JSONObject jsonObject = metadata.toJSONObject();

		assertTrue((Boolean) jsonObject.get("require_auth_time"));
	}


	public void testJOSEAlgEquality()
		throws Exception {

		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.applyDefaults();

		metadata.setIDTokenJWSAlg(JWSAlgorithm.RS256);
		metadata.setIDTokenJWEAlg(JWEAlgorithm.RSA1_5);
		metadata.setIDTokenJWEEnc(EncryptionMethod.A128GCM);

		metadata.setUserInfoJWSAlg(JWSAlgorithm.RS256);
		metadata.setUserInfoJWEAlg(JWEAlgorithm.RSA1_5);
		metadata.setUserInfoJWEEnc(EncryptionMethod.A128GCM);

		metadata.setRequestObjectJWSAlg(JWSAlgorithm.HS256);
		metadata.setRequestObjectJWEAlg(JWEAlgorithm.RSA1_5);
		metadata.setRequestObjectJWEEnc(EncryptionMethod.A128CBC_HS256);

		metadata = OIDCClientMetadata.parse(JSONObjectUtils.parse(metadata.toJSONObject().toJSONString()));

		assertEquals(JWSAlgorithm.RS256, metadata.getIDTokenJWSAlg());
		assertEquals(JWEAlgorithm.RSA1_5, metadata.getIDTokenJWEAlg());
		assertEquals(EncryptionMethod.A128GCM, metadata.getIDTokenJWEEnc());

		assertEquals(JWSAlgorithm.RS256, metadata.getUserInfoJWSAlg());
		assertEquals(JWEAlgorithm.RSA1_5, metadata.getUserInfoJWEAlg());
		assertEquals(EncryptionMethod.A128GCM, metadata.getIDTokenJWEEnc());

		assertEquals(JWSAlgorithm.HS256, metadata.getRequestObjectJWSAlg());
		assertEquals(JWEAlgorithm.RSA1_5, metadata.getRequestObjectJWEAlg());
		assertEquals(EncryptionMethod.A128CBC_HS256, metadata.getRequestObjectJWEEnc());
	}


	public void testJOSEEncMethodParseWithCEKCheck()
		throws Exception {

		// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issue/127/oidcclient-parse-method-causes-potential

		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.applyDefaults();

		metadata.setIDTokenJWEEnc(EncryptionMethod.A128GCM);
		metadata.setUserInfoJWEEnc(EncryptionMethod.A128GCM);
		metadata.setRequestObjectJWEEnc(EncryptionMethod.A128CBC_HS256);

		metadata = OIDCClientMetadata.parse(JSONObjectUtils.parse(metadata.toJSONObject().toJSONString()));

		assertEquals(128, metadata.getIDTokenJWEEnc().cekBitLength());
		assertEquals(128, metadata.getUserInfoJWEEnc().cekBitLength());
		assertEquals(256, metadata.getRequestObjectJWEEnc().cekBitLength());
	}


	public void testClientAuthNoneWithImplicitGrant() {

		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setGrantTypes(Collections.singleton(GrantType.IMPLICIT));
		clientMetadata.setResponseTypes(Collections.singleton(new ResponseType("token")));

		clientMetadata.applyDefaults();

		assertEquals(Collections.singleton(GrantType.IMPLICIT), clientMetadata.getGrantTypes());
		assertEquals(Collections.singleton(new ResponseType("token")), clientMetadata.getResponseTypes());
		assertEquals(ClientAuthenticationMethod.NONE, clientMetadata.getTokenEndpointAuthMethod());
	}


	public void testInvalidClientMetadataErrorCode() {

		JSONObject o = new JSONObject();
		o.put("application_type", "xyz");

		try {
			OIDCClientMetadata.parse(o);
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected value of JSON object member with key \"application_type\"", e.getMessage());
			assertEquals(RegistrationError.INVALID_CLIENT_METADATA.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid client metadata field: Unexpected value of JSON object member with key \"application_type\"", e.getErrorObject().getDescription());
		}
	}


	public void testSectorIdentifierURICheck() {

		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();

		try {
			clientMetadata.setSectorIDURI(URI.create("http://example.com/callbacks.json"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The URI must have a https scheme", e.getMessage());
		}

		try {
			clientMetadata.setSectorIDURI(URI.create("https:///callbacks.json"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The URI must contain a host component", e.getMessage());
		}
	}


	public void testResolveSectorIdentifier_simpleCase() {

		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setSubjectType(SubjectType.PAIRWISE);
		clientMetadata.setRedirectionURI(URI.create("https://example.com/callback"));
		assertEquals(new SectorID("example.com"), clientMetadata.resolveSectorID());
	}


	public void testResolveSectorIdentifier_fromSectorIDURI_opt() {

		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setSubjectType(SubjectType.PAIRWISE);
		clientMetadata.setRedirectionURI(URI.create("https://myapp.com/callback"));
		clientMetadata.setSectorIDURI(URI.create("https://example.com/apps.json"));
		assertEquals(new SectorID("example.com"), clientMetadata.resolveSectorID());
	}


	public void testResolveSectorIdentifier_fromSectorIDURI_required() {

		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setSubjectType(SubjectType.PAIRWISE);
		clientMetadata.setRedirectionURIs(new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback"))));
		clientMetadata.setSectorIDURI(URI.create("https://example.com/apps.json"));
		assertEquals(new SectorID("example.com"), clientMetadata.resolveSectorID());
	}


	public void testResolveSectorIdentifier_missingSectorIDURIError() {

		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setSubjectType(SubjectType.PAIRWISE);
		clientMetadata.setRedirectionURIs(new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback"))));
		try {
			clientMetadata.resolveSectorID();
		} catch (IllegalStateException e) {
			assertEquals("Couldn't resolve sector ID: More than one redirect_uri, sector_identifier_uri not specified", e.getMessage());
		}
	}


	public void testResolveSectorIdentifier_missingRedirectURIError() {

		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setSubjectType(SubjectType.PAIRWISE);
		try {
			clientMetadata.resolveSectorID();
		} catch (IllegalStateException e) {
			assertEquals("Couldn't resolve sector ID: Missing redirect_uris", e.getMessage());
		}
	}


	public void testResolveSectorIdentifier_publicSubjectType() {

		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setSubjectType(SubjectType.PUBLIC);
		assertNull(clientMetadata.resolveSectorID());
	}


	public void testResolveSectorIdentifier_nullSubjectType() {

		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setSubjectType(null);
		assertNull(clientMetadata.resolveSectorID());
	}
	
	
	public void testOverrideToJSONObjectWithCustomFields() {
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
		clientMetadata.setSubjectType(SubjectType.PAIRWISE);
		clientMetadata.setSectorIDURI(URI.create("https://example.com/sector.json"));
		clientMetadata.applyDefaults();
		
		JSONObject jsonObject = clientMetadata.toJSONObject(true);
		assertNotNull(jsonObject.get("grant_types"));
		assertNotNull(jsonObject.get("response_types"));
		assertNotNull(jsonObject.get("redirect_uris"));
		assertNotNull(jsonObject.get("token_endpoint_auth_method"));
		assertNotNull(jsonObject.get("application_type"));
		assertNotNull(jsonObject.get("subject_type"));
		assertNotNull(jsonObject.get("sector_identifier_uri"));
		assertNotNull(jsonObject.get("id_token_signed_response_alg"));
		assertNull(jsonObject.get("tls_client_certificate_bound_access_tokens"));
		
		assertEquals(8, jsonObject.size());
	}
	
	
	public void testPermitParseNullValues()
		throws Exception {
		
		JSONObject jsonObject = new JSONObject();
		
		for (String paramName: OIDCClientMetadata.getRegisteredParameterNames()) {
			
			jsonObject.put(paramName, null);
		}
		
		OIDCClientMetadata.parse(jsonObject);
	}
	
	
	public void testJSONObjectFrontChannelLogoutParams()
		throws ParseException {
		
		URI logoutURI = URI.create("https://example.com/logout/front-channel");
		
		// default
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.applyDefaults();
		JSONObject out = clientMetadata.toJSONObject();
		assertNull(out.get("frontchannel_logout_uri"));
		assertNull(out.get("frontchannel_logout_session_required"));
		
		// with logout URI
		clientMetadata.setFrontChannelLogoutURI(logoutURI);
		out = clientMetadata.toJSONObject();
		assertEquals(logoutURI.toString(), out.get("frontchannel_logout_uri"));
		assertFalse((Boolean)out.get("frontchannel_logout_session_required"));
		
		clientMetadata = OIDCClientMetadata.parse(out);
		assertEquals(logoutURI, clientMetadata.getFrontChannelLogoutURI());
		assertFalse(clientMetadata.requiresFrontChannelLogoutSession());
		
		// with logout URI and SID requirement
		clientMetadata.requiresFrontChannelLogoutSession(true);
		out = clientMetadata.toJSONObject();
		assertEquals(logoutURI.toString(), out.get("frontchannel_logout_uri"));
		assertTrue((Boolean)out.get("frontchannel_logout_session_required"));
		
		clientMetadata = OIDCClientMetadata.parse(out);
		assertEquals(logoutURI, clientMetadata.getFrontChannelLogoutURI());
		assertTrue(clientMetadata.requiresFrontChannelLogoutSession());
		
		// with logout URI and SID requirement defaulting to false
		clientMetadata.requiresFrontChannelLogoutSession(false);
		out = clientMetadata.toJSONObject();
		assertEquals(logoutURI.toString(), out.get("frontchannel_logout_uri"));
		assertFalse((Boolean)out.remove("frontchannel_logout_session_required"));
		
		clientMetadata = OIDCClientMetadata.parse(out);
		assertEquals(logoutURI, clientMetadata.getFrontChannelLogoutURI());
		assertFalse(clientMetadata.requiresFrontChannelLogoutSession());
	}
	
	
	public void testJSONObjectBackChannelLogoutParams()
		throws ParseException {
		
		URI logoutURI = URI.create("https://example.com/logout/back-channel");
		
		// default
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.applyDefaults();
		JSONObject out = clientMetadata.toJSONObject();
		assertNull(out.get("backchannel_logout_uri"));
		assertNull(out.get("backchannel_logout_session_required"));
		
		// with logout URI
		clientMetadata.setBackChannelLogoutURI(logoutURI);
		out = clientMetadata.toJSONObject();
		assertEquals(logoutURI.toString(), out.get("backchannel_logout_uri"));
		assertFalse((Boolean)out.get("backchannel_logout_session_required"));
		
		clientMetadata = OIDCClientMetadata.parse(out);
		assertEquals(logoutURI, clientMetadata.getBackChannelLogoutURI());
		assertFalse(clientMetadata.requiresBackChannelLogoutSession());
		
		// with logout URI and SID requirement
		clientMetadata.requiresBackChannelLogoutSession(true);
		out = clientMetadata.toJSONObject();
		assertEquals(logoutURI.toString(), out.get("backchannel_logout_uri"));
		assertTrue((Boolean)out.get("backchannel_logout_session_required"));
		
		clientMetadata = OIDCClientMetadata.parse(out);
		assertEquals(logoutURI, clientMetadata.getBackChannelLogoutURI());
		assertTrue(clientMetadata.requiresBackChannelLogoutSession());
		
		// with logout URI and SID requirement defaulting to false
		clientMetadata.requiresBackChannelLogoutSession(false);
		out = clientMetadata.toJSONObject();
		assertEquals(logoutURI.toString(), out.get("backchannel_logout_uri"));
		assertFalse((Boolean)out.remove("backchannel_logout_session_required"));
		
		clientMetadata = OIDCClientMetadata.parse(out);
		assertEquals(logoutURI, clientMetadata.getBackChannelLogoutURI());
		assertFalse(clientMetadata.requiresBackChannelLogoutSession());
	}
	
	
	public void testJARM()
		throws ParseException {
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		
		assertNull(clientMetadata.getAuthorizationJWSAlg());
		assertNull(clientMetadata.getAuthorizationJWEAlg());
		assertNull(clientMetadata.getAuthorizationJWEEnc());
		
		clientMetadata.setAuthorizationJWSAlg(JWSAlgorithm.ES256);
		assertEquals(JWSAlgorithm.ES256, clientMetadata.getAuthorizationJWSAlg());
		
		clientMetadata.setAuthorizationJWEAlg(JWEAlgorithm.ECDH_ES);
		assertEquals(JWEAlgorithm.ECDH_ES, clientMetadata.getAuthorizationJWEAlg());
		
		clientMetadata.setAuthorizationJWEEnc(EncryptionMethod.A256GCM);
		assertEquals(EncryptionMethod.A256GCM, clientMetadata.getAuthorizationJWEEnc());
		
		JSONObject jsonObject = clientMetadata.toJSONObject();
		
		assertEquals(JWSAlgorithm.ES256.getName(), jsonObject.get("authorization_signed_response_alg"));
		assertEquals(JWEAlgorithm.ECDH_ES.getName(), jsonObject.get("authorization_encrypted_response_alg"));
		assertEquals(EncryptionMethod.A256GCM.getName(), jsonObject.get("authorization_encrypted_response_enc"));
		
		clientMetadata = OIDCClientMetadata.parse(jsonObject);
		
		assertEquals(JWSAlgorithm.ES256, clientMetadata.getAuthorizationJWSAlg());
		assertEquals(JWEAlgorithm.ECDH_ES, clientMetadata.getAuthorizationJWEAlg());
		assertEquals(EncryptionMethod.A256GCM, clientMetadata.getAuthorizationJWEEnc());
	}
	
	
	public void testFederationFields()
		throws Exception {
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		
		URI redirectionURI = URI.create("https://example.com/cb");
		clientMetadata.setRedirectionURI(redirectionURI);
		
		assertNull(clientMetadata.getFederationTypes());
		List<ClientRegistrationType> federationTypes = Arrays.asList(ClientRegistrationType.EXPLICIT, ClientRegistrationType.AUTOMATIC);
		clientMetadata.setFederationTypes(federationTypes);
		assertEquals(federationTypes, clientMetadata.getFederationTypes());
		
		assertNull(clientMetadata.getOrganizationName());
		String orgName = "Example Org";
		clientMetadata.setOrganizationName(orgName);
		assertEquals(orgName, clientMetadata.getOrganizationName());
		
		JSONObject jsonObject = clientMetadata.toJSONObject();
		
		assertEquals(Arrays.asList("explicit", "automatic"), JSONObjectUtils.getStringList(jsonObject, "federation_type"));
		assertEquals(orgName, JSONObjectUtils.getString(jsonObject, "organization_name"));
		
		clientMetadata = OIDCClientMetadata.parse(jsonObject);
		
		assertEquals(redirectionURI, clientMetadata.getRedirectionURI());
		assertEquals(federationTypes, clientMetadata.getFederationTypes());
		assertEquals(orgName, clientMetadata.getOrganizationName());
	}
}