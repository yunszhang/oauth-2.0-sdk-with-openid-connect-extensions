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
import java.util.*;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerEndpointMetadata;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * OpenID Provider (OP) endpoint metadata.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Authorization Server Metadata (RFC 8414)
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (draft-ietf-oauth-mtls-17)
 *     <li>OAuth 2.0 Device Flow for Browserless and Input Constrained Devices
 *         (draft-ietf-oauth-device-flow-14)
 *     <li>OpenID Connect Discovery 1.0, section 3.
 *     <li>OpenID Connect Session Management 1.0, section 2.1 (draft 28).
 *     <li>OpenID Connect Front-Channel Logout 1.0, section 3 (draft 02).
 *     <li>OpenID Connect Back-Channel Logout 1.0, section 2.1 (draft 04).
 *     <li>OpenID Connect Federation 1.0 (draft 10).
 * </ul>
 */
public class OIDCProviderEndpointMetadata extends AuthorizationServerEndpointMetadata {
	
	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;
	
	
	static {
		Set<String> p = new HashSet<>(AuthorizationServerEndpointMetadata.getRegisteredParameterNames());
		p.add("userinfo_endpoint");
		p.add("federation_registration_endpoint");
		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}
	
	
	/**
	 * Gets the registered provider metadata parameter names for endpoints.
	 *
	 * @return The registered provider metadata parameter names for the
	 *         endpoints, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {
		
		return REGISTERED_PARAMETER_NAMES;
	}
	
	
	/**
	 * The UserInfo endpoint.
	 */
	private URI userInfoEndpoint;
	
	
	/**
	 * The federation registration endpoint.
	 */
	private URI federationRegistrationEndpoint;
	
	
	/**
	 * Creates a new OpenID Connect provider endpoint metadata instance.
	 */
	public OIDCProviderEndpointMetadata() {
	}
	
	
	/**
	 * Converts an authorization server endpoint metadata to an OpenID
	 * Connect provider endpoint metadata instance.
	 */
	public OIDCProviderEndpointMetadata(final AuthorizationServerEndpointMetadata mtlsEndpointAliases) {

		setAuthorizationEndpointURI(mtlsEndpointAliases.getAuthorizationEndpointURI());
		setTokenEndpointURI(mtlsEndpointAliases.getTokenEndpointURI());
		setRegistrationEndpointURI(mtlsEndpointAliases.getRegistrationEndpointURI());
		setIntrospectionEndpointURI(mtlsEndpointAliases.getIntrospectionEndpointURI());
		setRevocationEndpointURI(mtlsEndpointAliases.getRevocationEndpointURI());
		setDeviceAuthorizationEndpointURI(mtlsEndpointAliases.getDeviceAuthorizationEndpointURI());
		setPushedAuthorizationRequestEndpointURI(mtlsEndpointAliases.getPushedAuthorizationRequestEndpointURI());
		setRequestObjectEndpoint(mtlsEndpointAliases.getRequestObjectEndpoint());
	}


	/**
	 * Gets the UserInfo endpoint URI. Corresponds the
	 * {@code userinfo_endpoint} metadata field.
	 *
	 * @return The UserInfo endpoint URI, {@code null} if not specified.
	 */
	public URI getUserInfoEndpointURI() {

		return userInfoEndpoint;
	}


	/**
	 * Sets the UserInfo endpoint URI. Corresponds the
	 * {@code userinfo_endpoint} metadata field.
	 *
	 * @param userInfoEndpoint The UserInfo endpoint URI, {@code null} if
	 *                         not specified.
	 */
	public void setUserInfoEndpointURI(final URI userInfoEndpoint) {

		this.userInfoEndpoint = userInfoEndpoint;
	}
	
	
	/**
	 * Gets the federation registration endpoint URI. Corresponds to the
	 * {@code federation_registration_endpoint} metadata field.
	 *
	 * @return The federation registration endpoint URI, {@code null} if
	 *         not specified.
	 */
	public URI getFederationRegistrationEndpointURI() {
		
		return federationRegistrationEndpoint;
	}
	
	
	/**
	 * Sets the federation registration endpoint URI. Corresponds to the
	 * {@code federation_registration_endpoint} metadata field.
	 *
	 * @param federationRegistrationEndpoint The federation registration
	 *                                       endpoint URI, {@code null} if
	 *                                       not specified.
	 */
	public void setFederationRegistrationEndpointURI(final URI federationRegistrationEndpoint) {
		
		this.federationRegistrationEndpoint = federationRegistrationEndpoint;
	}
	
	
	/**
	 * Returns the JSON object representation of this OpenID Connect
	 * provider metadata.
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject o = super.toJSONObject();
		
		if (userInfoEndpoint != null)
			o.put("userinfo_endpoint", userInfoEndpoint.toString());
		
		if (federationRegistrationEndpoint != null)
			o.put("federation_registration_endpoint", federationRegistrationEndpoint.toString());
		
		return o;
	}
	
	
	/**
	 * Parses an OAuth 2.0 Authorisation Server endpoint metadata from the specified
	 * JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The OAuth 2.0 Authorisation Server endpoint metadata.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OAuth 2.0 Authorisation Server endpoint metadata.
	 */
	public static OIDCProviderEndpointMetadata parse(final JSONObject jsonObject)
		throws ParseException {

		AuthorizationServerEndpointMetadata as = AuthorizationServerEndpointMetadata.parse(jsonObject);

		OIDCProviderEndpointMetadata op = new OIDCProviderEndpointMetadata();
		
		op.setAuthorizationEndpointURI(as.getAuthorizationEndpointURI());
		op.setTokenEndpointURI(as.getTokenEndpointURI());
		op.setRegistrationEndpointURI(as.getRegistrationEndpointURI());
		op.setIntrospectionEndpointURI(as.getIntrospectionEndpointURI());
		op.setRevocationEndpointURI(as.getRevocationEndpointURI());
		op.setDeviceAuthorizationEndpointURI(as.getDeviceAuthorizationEndpointURI());
		op.setPushedAuthorizationRequestEndpointURI(as.getPushedAuthorizationRequestEndpointURI());
		op.setRequestObjectEndpoint(as.getRequestObjectEndpoint());
		op.userInfoEndpoint = JSONObjectUtils.getURI(jsonObject, "userinfo_endpoint", null);
		op.federationRegistrationEndpoint = JSONObjectUtils.getURI(jsonObject, "federation_registration_endpoint", null);
		
		return op;
	}
}
