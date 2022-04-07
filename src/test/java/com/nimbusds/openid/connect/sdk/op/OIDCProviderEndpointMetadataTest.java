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

package com.nimbusds.openid.connect.sdk.op;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerEndpointMetadata;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


public class OIDCProviderEndpointMetadataTest extends TestCase {
	
	
	public void testRegisteredParameters() {
		
		Set<String> paramNames = OIDCProviderEndpointMetadata.getRegisteredParameterNames();
		
		// OAuth
		assertTrue(paramNames.contains("authorization_endpoint"));
		assertTrue(paramNames.contains("token_endpoint"));
		assertTrue(paramNames.contains("registration_endpoint"));
		assertTrue(paramNames.contains("pushed_authorization_request_endpoint"));
		assertTrue(paramNames.contains("request_object_endpoint"));
		assertTrue(paramNames.contains("introspection_endpoint"));
		assertTrue(paramNames.contains("revocation_endpoint"));
		assertTrue(paramNames.contains("device_authorization_endpoint"));
		assertTrue(paramNames.contains("backchannel_authentication_endpoint"));
		
		// OIDC
		assertTrue(paramNames.contains("userinfo_endpoint"));
		assertTrue(paramNames.contains("check_session_iframe"));
		assertTrue(paramNames.contains("end_session_endpoint"));
		assertTrue(paramNames.contains("federation_registration_endpoint"));
		assertEquals(13, paramNames.size());
	}


	public void testEmpty() throws ParseException {
		
		OIDCProviderEndpointMetadata endpointMetadata = new OIDCProviderEndpointMetadata();
		
		// OAuth
		assertNull(endpointMetadata.getAuthorizationEndpointURI());
		assertNull(endpointMetadata.getTokenEndpointURI());
		assertNull(endpointMetadata.getRegistrationEndpointURI());
		assertNull(endpointMetadata.getPushedAuthorizationRequestEndpointURI());
		assertNull(endpointMetadata.getRequestObjectEndpoint());
		assertNull(endpointMetadata.getIntrospectionEndpointURI());
		assertNull(endpointMetadata.getRevocationEndpointURI());
		assertNull(endpointMetadata.getDeviceAuthorizationEndpointURI());
		assertNull(endpointMetadata.getBackChannelAuthenticationEndpointURI());
		assertNull(endpointMetadata.getBackChannelAuthenticationEndpoint());
		
		// OIDC
		assertNull(endpointMetadata.getUserInfoEndpointURI());
		assertNull(endpointMetadata.getCheckSessionIframeURI());
		assertNull(endpointMetadata.getEndSessionEndpointURI());
		assertNull(endpointMetadata.getFederationRegistrationEndpointURI());
		
		JSONObject jsonObject = endpointMetadata.toJSONObject();
		
		ReadOnlyOIDCProviderEndpointMetadata parsedEndpointMetadata = OIDCProviderEndpointMetadata.parse(jsonObject);
		
		// OAuth
		assertNull(parsedEndpointMetadata.getAuthorizationEndpointURI());
		assertNull(parsedEndpointMetadata.getTokenEndpointURI());
		assertNull(parsedEndpointMetadata.getRegistrationEndpointURI());
		assertNull(parsedEndpointMetadata.getPushedAuthorizationRequestEndpointURI());
		assertNull(parsedEndpointMetadata.getRequestObjectEndpoint());
		assertNull(parsedEndpointMetadata.getIntrospectionEndpointURI());
		assertNull(parsedEndpointMetadata.getRevocationEndpointURI());
		assertNull(parsedEndpointMetadata.getDeviceAuthorizationEndpointURI());
		assertNull(parsedEndpointMetadata.getBackChannelAuthenticationEndpointURI());
		assertNull(parsedEndpointMetadata.getBackChannelAuthenticationEndpoint());
		
		// OIDC
		assertNull(parsedEndpointMetadata.getUserInfoEndpointURI());
		assertNull(parsedEndpointMetadata.getCheckSessionIframeURI());
		assertNull(parsedEndpointMetadata.getEndSessionEndpointURI());
		assertNull(parsedEndpointMetadata.getFederationRegistrationEndpointURI());
	}
	
	
	public void testGettersAndSetters() throws ParseException, URISyntaxException {
		
		OIDCProviderEndpointMetadata endpointMetadata = new OIDCProviderEndpointMetadata();
		
		endpointMetadata.setAuthorizationEndpointURI(new URI("https://c2id.com/authz"));
		assertEquals(new URI("https://c2id.com/authz"), endpointMetadata.getAuthorizationEndpointURI());
		
		endpointMetadata.setTokenEndpointURI(new URI("https://c2id.com/token"));
		assertEquals(new URI("https://c2id.com/token"), endpointMetadata.getTokenEndpointURI());
		
		endpointMetadata.setRegistrationEndpointURI(new URI("https://c2id.com/reg"));
		assertEquals(new URI("https://c2id.com/reg"), endpointMetadata.getRegistrationEndpointURI());
		
		endpointMetadata.setIntrospectionEndpointURI(new URI("https://c2id.com/inspect"));
		assertEquals(new URI("https://c2id.com/inspect"), endpointMetadata.getIntrospectionEndpointURI());
		
		endpointMetadata.setRevocationEndpointURI(new URI("https://c2id.com/revoke"));
		assertEquals(new URI("https://c2id.com/revoke"), endpointMetadata.getRevocationEndpointURI());
		
		endpointMetadata.setPushedAuthorizationRequestEndpointURI(new URI("https://c2id.com/par"));
		assertEquals(new URI("https://c2id.com/par"), endpointMetadata.getPushedAuthorizationRequestEndpointURI());
		
		endpointMetadata.setRequestObjectEndpoint(new URI("https://c2id.com/jar"));
		assertEquals(new URI("https://c2id.com/jar"), endpointMetadata.getRequestObjectEndpoint());
		
		endpointMetadata.setDeviceAuthorizationEndpointURI(new URI("https://c2id.com/device"));
		assertEquals(new URI("https://c2id.com/device"), endpointMetadata.getDeviceAuthorizationEndpointURI());
		
		endpointMetadata.setBackChannelAuthenticationEndpointURI(new URI("https://c2id.com/ciba"));
		assertEquals(new URI("https://c2id.com/ciba"), endpointMetadata.getBackChannelAuthenticationEndpointURI());
		
		endpointMetadata.setUserInfoEndpointURI(new URI("https://c2id.com/userinfo"));
		assertEquals(new URI("https://c2id.com/userinfo"), endpointMetadata.getUserInfoEndpointURI());
		
		endpointMetadata.setCheckSessionIframeURI(new URI("https://c2id.com/session"));
		assertEquals(new URI("https://c2id.com/session"), endpointMetadata.getCheckSessionIframeURI());
		
		endpointMetadata.setEndSessionEndpointURI(new URI("https://c2id.com/logout"));
		assertEquals(new URI("https://c2id.com/logout"), endpointMetadata.getEndSessionEndpointURI());
		
		endpointMetadata.setFederationRegistrationEndpointURI(new URI("https://c2id.com/fed"));
		assertEquals(new URI("https://c2id.com/fed"), endpointMetadata.getFederationRegistrationEndpointURI());
		
		JSONObject jsonObject = endpointMetadata.toJSONObject();
		
		for (String paramName: OIDCProviderEndpointMetadata.getRegisteredParameterNames()) {
			assertTrue(paramName, jsonObject.containsKey(paramName));
		}
		
		endpointMetadata = OIDCProviderEndpointMetadata.parse(jsonObject);
		
		assertEquals(new URI("https://c2id.com/authz"), endpointMetadata.getAuthorizationEndpointURI());
		assertEquals(new URI("https://c2id.com/token"), endpointMetadata.getTokenEndpointURI());
		assertEquals(new URI("https://c2id.com/reg"), endpointMetadata.getRegistrationEndpointURI());
		assertEquals(new URI("https://c2id.com/inspect"), endpointMetadata.getIntrospectionEndpointURI());
		assertEquals(new URI("https://c2id.com/revoke"), endpointMetadata.getRevocationEndpointURI());
		assertEquals(new URI("https://c2id.com/par"), endpointMetadata.getPushedAuthorizationRequestEndpointURI());
		assertEquals(new URI("https://c2id.com/jar"), endpointMetadata.getRequestObjectEndpoint());
		assertEquals(new URI("https://c2id.com/device"), endpointMetadata.getDeviceAuthorizationEndpointURI());
		assertEquals(new URI("https://c2id.com/ciba"), endpointMetadata.getBackChannelAuthenticationEndpointURI());
		assertEquals(new URI("https://c2id.com/ciba"), endpointMetadata.getBackChannelAuthenticationEndpoint());
		assertEquals(new URI("https://c2id.com/userinfo"), endpointMetadata.getUserInfoEndpointURI());
		assertEquals(new URI("https://c2id.com/session"), endpointMetadata.getCheckSessionIframeURI());
		assertEquals(new URI("https://c2id.com/logout"), endpointMetadata.getEndSessionEndpointURI());
		assertEquals(new URI("https://c2id.com/fed"), endpointMetadata.getFederationRegistrationEndpointURI());
	}
	
	
	public void testDeprecatedCIBAEndpointGetterAndSetter() throws ParseException, URISyntaxException {
		
		OIDCProviderEndpointMetadata endpointMetadata = new OIDCProviderEndpointMetadata();
		
		endpointMetadata.setBackChannelAuthenticationEndpoint(new URI("https://c2id.com/ciba"));
		assertEquals(new URI("https://c2id.com/ciba"), endpointMetadata.getBackChannelAuthenticationEndpoint());
		
		JSONObject jsonObject = endpointMetadata.toJSONObject();
		assertEquals("https://c2id.com/ciba", jsonObject.get("backchannel_authentication_endpoint"));
		assertEquals(1, jsonObject.size());
		
		endpointMetadata = OIDCProviderEndpointMetadata.parse(jsonObject);
		
		assertEquals(new URI("https://c2id.com/ciba"), endpointMetadata.getBackChannelAuthenticationEndpoint());
	}
	
	
	public void testCopyConstructor() throws URISyntaxException {
		
		AuthorizationServerEndpointMetadata asEndpointMetadata = new AuthorizationServerEndpointMetadata();
		
		asEndpointMetadata.setAuthorizationEndpointURI(new URI("https://c2id.com/authz"));
		asEndpointMetadata.setTokenEndpointURI(new URI("https://c2id.com/token"));
		asEndpointMetadata.setRegistrationEndpointURI(new URI("https://c2id.com/reg"));
		asEndpointMetadata.setIntrospectionEndpointURI(new URI("https://c2id.com/inspect"));
		asEndpointMetadata.setRevocationEndpointURI(new URI("https://c2id.com/revoke"));
		asEndpointMetadata.setPushedAuthorizationRequestEndpointURI(new URI("https://c2id.com/par"));
		asEndpointMetadata.setRequestObjectEndpoint(new URI("https://c2id.com/jar"));
		asEndpointMetadata.setDeviceAuthorizationEndpointURI(new URI("https://c2id.com/device"));
		asEndpointMetadata.setBackChannelAuthenticationEndpointURI(new URI("https://c2id.com/ciba"));
		
		ReadOnlyOIDCProviderEndpointMetadata opEndpointMetadata = new OIDCProviderEndpointMetadata(asEndpointMetadata);
		assertEquals(new URI("https://c2id.com/authz"), opEndpointMetadata.getAuthorizationEndpointURI());
		assertEquals(new URI("https://c2id.com/token"), opEndpointMetadata.getTokenEndpointURI());
		assertEquals(new URI("https://c2id.com/reg"), opEndpointMetadata.getRegistrationEndpointURI());
		assertEquals(new URI("https://c2id.com/inspect"), opEndpointMetadata.getIntrospectionEndpointURI());
		assertEquals(new URI("https://c2id.com/revoke"), opEndpointMetadata.getRevocationEndpointURI());
		assertEquals(new URI("https://c2id.com/par"), opEndpointMetadata.getPushedAuthorizationRequestEndpointURI());
		assertEquals(new URI("https://c2id.com/jar"), opEndpointMetadata.getRequestObjectEndpoint());
		assertEquals(new URI("https://c2id.com/device"), opEndpointMetadata.getDeviceAuthorizationEndpointURI());
		assertEquals(new URI("https://c2id.com/ciba"), opEndpointMetadata.getBackChannelAuthenticationEndpointURI());
		assertNull(opEndpointMetadata.getUserInfoEndpointURI());
		assertNull(opEndpointMetadata.getCheckSessionIframeURI());
		assertNull(opEndpointMetadata.getEndSessionEndpointURI());
		assertNull(opEndpointMetadata.getFederationRegistrationEndpointURI());
	}
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/373/exception-thrown-when-calling#comment-62053807
	public void testParseSampleWithUndefinedAuthorizationEndpoint() throws ParseException {
		
		String json ="{"+
			"\"token_endpoint\":\"https://keycloakdomain/auth/realms/tcw/protocol/openid-connect/token\","+
			"\"revocation_endpoint\":\"https://keycloakdomain/auth/realms/tcw/protocol/openid-connect/revoke\","+
			"\"introspection_endpoint\":\"https://keycloakdomain/auth/realms/tcw/protocol/openid-connect/token/introspect\","+
			"\"device_authorization_endpoint\":\"https://keycloakdomain/auth/realms/tcw/protocol/openid-connect/auth/device\","+
			"\"registration_endpoint\":\"https://keycloakdomain/auth/realms/tcw/clients-registrations/openid-connect\","+
			"\"userinfo_endpoint\":\"https://keycloakdomain/auth/realms/tcw/protocol/openid-connect/userinfo\","+
			"\"pushed_authorization_request_endpoint\":\"https://keycloakdomain/auth/realms/tcw/protocol/openid-connect/ext/par/request\","+
			"\"backchannel_authentication_endpoint\":\"https://keycloakdomain/auth/realms/tcw/protocol/openid-connect/ext/ciba/auth\""+
			"}";
		
		OIDCProviderEndpointMetadata endpointMetadata = OIDCProviderEndpointMetadata.parse(JSONObjectUtils.parse(json));
		
		assertEquals(URI.create("https://keycloakdomain/auth/realms/tcw/protocol/openid-connect/token"), endpointMetadata.getTokenEndpointURI());
		assertEquals(URI.create("https://keycloakdomain/auth/realms/tcw/protocol/openid-connect/revoke"), endpointMetadata.getRevocationEndpointURI());
		assertEquals(URI.create("https://keycloakdomain/auth/realms/tcw/protocol/openid-connect/token/introspect"), endpointMetadata.getIntrospectionEndpointURI());
		assertEquals(URI.create("https://keycloakdomain/auth/realms/tcw/protocol/openid-connect/auth/device"), endpointMetadata.getDeviceAuthorizationEndpointURI());
		assertEquals(URI.create("https://keycloakdomain/auth/realms/tcw/clients-registrations/openid-connect"), endpointMetadata.getRegistrationEndpointURI());
		assertEquals(URI.create("https://keycloakdomain/auth/realms/tcw/protocol/openid-connect/userinfo"), endpointMetadata.getUserInfoEndpointURI());
		assertEquals(URI.create("https://keycloakdomain/auth/realms/tcw/protocol/openid-connect/ext/par/request"), endpointMetadata.getPushedAuthorizationRequestEndpointURI());
		assertEquals(URI.create("https://keycloakdomain/auth/realms/tcw/protocol/openid-connect/ext/ciba/auth"), endpointMetadata.getBackChannelAuthenticationEndpointURI());
		
		assertNull(endpointMetadata.getAuthorizationEndpointURI());
	}
}
