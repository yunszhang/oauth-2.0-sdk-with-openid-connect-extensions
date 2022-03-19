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


import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ciba.CIBARequest;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;


/**
 * Resolved authentication Context Class Reference (ACR) request.
 */
@Immutable 
public final class ACRRequest {


	/**
	 * The essential ACR values.
	 */
	private final List<ACR> essentialACRs;


	/**
	 * The voluntary ACR values.
	 */
	private final List<ACR> voluntaryACRs;


	/**
	 * Creates a new Authentication Context Class Reference (ACR) request.
	 *
	 * @param essentialACRs The requested essential ACR values, by order of
	 *                      preference, {@code null} if not specified.
	 * @param voluntaryACRs The requested voluntary ACR values, by order of
	 *                      preference, {@code null} if not specified.
	 */
	public ACRRequest(final List<ACR> essentialACRs, final List<ACR> voluntaryACRs) {

		this.essentialACRs = essentialACRs;
		this.voluntaryACRs = voluntaryACRs;
	}
	

	/**
	 * Gets the requested essential ACR values.
	 * 
	 * @return The essential ACR values, by order of preference, 
	 *         {@code null} if not specified.
	 */
	public List<ACR> getEssentialACRs() {
		
		return essentialACRs;
	}
	
	
	/**
	 * Gets the requested voluntary ACR values.
	 * 
	 * @return The voluntary ACR values, by order of preference, 
	 *         {@code null} if not specified.
	 */
	public List<ACR> getVoluntaryACRs() {
		
		return voluntaryACRs;
	}
	
	
	/**
	 * Checks if this ACR request has no essential or voluntary values
	 * specified.
	 * 
	 * @return {@code true} if this ACR request doesn't specify any 
	 *         essential or voluntary values, else {@code false}.
	 */
	public boolean isEmpty() {

		return !(essentialACRs != null && !essentialACRs.isEmpty()) &&
		       !(voluntaryACRs != null && !voluntaryACRs.isEmpty());
	}
	
	
	/**
	 * Applies the registered default ACR values for the requesting client
	 * (as a voluntary ACR value, provided no ACR values were explicitly
	 * requested).
	 *
	 * @param clientInfo The registered client information. Must not be
	 *                   {@code null}.
	 *
	 * @return The ACR request, updated if registered default ACR values
	 *         were applied.
	 */
	public ACRRequest applyDefaultACRs(final OIDCClientInformation clientInfo) {
		
		// Apply default ACR from client reg store as voluntary?
		if (isEmpty()) {
			if (clientInfo.getOIDCMetadata().getDefaultACRs() != null) {
				List<ACR> voluntaryACRs = new LinkedList<>(clientInfo.getOIDCMetadata().getDefaultACRs());
				return new ACRRequest(null, voluntaryACRs);
			}
		}
		
		return this;
	}
	
	
	/**
	 * Ensures all requested essential ACR values are supported by those
	 * supported by the OpenID provider.
	 *
	 * @param authzRequest  The OAuth 2.0 authorisation request / OpenID
	 *                      authentication request. Must not be
	 *                      {@code null}.
	 * @param supportedACRs The ACR values supported by the OpenID
	 *                      provider, {@code null} if not specified.
	 *
	 * @throws GeneralException If a requested essential ACR value is not
	 *                          supported by the OpenID provider.
	 */
	public void ensureACRSupport(final AuthorizationRequest authzRequest, final List<ACR> supportedACRs)
		throws GeneralException {
		
		// Ensure any requested essential ACR is supported
		if (getEssentialACRs() != null) {
			
			boolean foundSupportedEssentialACR = false;
			
			for (ACR acr: getEssentialACRs()) {
				
				if (supportedACRs != null && supportedACRs.contains(acr)) {
					foundSupportedEssentialACR = true;
					break;
				}
			}
			
			if (! foundSupportedEssentialACR) {
				String msg = "Requested essential ACR(s) not supported";
				throw new GeneralException(msg,
					OAuth2Error.ACCESS_DENIED.appendDescription(": " + msg),
					authzRequest.getClientID(),
					authzRequest.getRedirectionURI(),
					authzRequest.impliedResponseMode(),
					authzRequest.getState());
			}
		}
	}
	
	
	/**
	 * Ensures all requested essential ACR values are supported by the
	 * OpenID provider.
	 *
	 * @param authRequest The OpenID authentication request. Must not be
	 *                    {@code null}.
	 * @param opMetadata  The OpenID provider metadata. Must not be
	 *                    {@code null}.
	 *
	 * @throws GeneralException If a requested essential ACR value is not
	 *                          supported by the OpenID provider.
	 */
	@Deprecated
	public void ensureACRSupport(final AuthenticationRequest authRequest, final OIDCProviderMetadata opMetadata)
		throws GeneralException {
		
		ensureACRSupport(authRequest, opMetadata.getACRs());
	}
	
	
	/**
	 * Resolves the requested essential and voluntary ACR values from the
	 * specified OAuth 2.0 authorisation request / OpenID authentication
	 * request.
	 * 
	 * @param authzRequest The OAuth 2.0 authorisation request / OpenID
	 *                     authentication request. Should be resolved. Must
	 *                     not be {@code null}.
	 * 
	 * @return The resolved ACR request.
	 */
	public static ACRRequest resolve(final AuthorizationRequest authzRequest) {
		
		if (! (authzRequest instanceof AuthenticationRequest)) {
			// Plain OAuth 2.0
			return new ACRRequest(null, null);
		}
		
		// OpenID
		AuthenticationRequest authRequest = (AuthenticationRequest) authzRequest;
		
		// OpenID
		return resolve(authRequest.getACRValues(), authRequest.getOIDCClaims());
	}
	
	
	/**
	 * Resolves the requested essential and voluntary ACR values from the
	 * specified CIBA request.
	 *
	 * @param cibaRequest The CIBA request. Must be resolved and not
	 *                    {@code null}.
	 *
	 * @return The resolved ACR request.
	 */
	public static ACRRequest resolve(final CIBARequest cibaRequest) {
		
		if (cibaRequest.isSigned()) {
			throw new IllegalArgumentException("The CIBA request must be resolved (not signed)");
		}
		
		if (cibaRequest.getScope() != null && ! cibaRequest.getScope().contains(OIDCScopeValue.OPENID)) {
			// Plain OAuth 2.0
			return new ACRRequest(null, null);
		}
		
		// OpenID
		return resolve(cibaRequest.getACRValues(), cibaRequest.getOIDCClaims());
	}
	
	
	
	private static ClaimsSetRequest.Entry getACRClaimRequest(final OIDCClaimsRequest claimsRequest) {
		
		if (claimsRequest == null) {
			return null;
		}
		
		ClaimsSetRequest idTokenClaimsRequest = claimsRequest.getIDTokenClaimsRequest();
		
		if (idTokenClaimsRequest == null) {
			return null;
		}
		
		for (ClaimsSetRequest.Entry en: idTokenClaimsRequest.getEntries()) {
			if ("acr".equals(en.getClaimName())) {
				return en;
			}
		}
		return null;
	}
	
	
	/**
	 * Resolves the requested essential and voluntary ACR values from the
	 * specified top-level {@code acr_values} request parameter and
	 * {@code claims} request parameter.
	 *
	 * @param acrValues     The top-level {@code acr_values} request
	 *                      parameter, {@code null} if not specified.
	 * @param claimsRequest The OpenID {@code claims} request parameter,
	 *                      {@code null} if not specified.
	 *
	 * @return The resolved ACR request.
	 */
	public static ACRRequest resolve(final List<ACR> acrValues, final OIDCClaimsRequest claimsRequest) {
		
		List<ACR> essentialACRs = null;
		List<ACR> voluntaryACRs = null;
		
		ClaimsSetRequest.Entry en = getACRClaimRequest(claimsRequest);
		
		if (en != null) {
			if (en.getClaimRequirement().equals(ClaimRequirement.ESSENTIAL)) {
				
				essentialACRs = new ArrayList<>();
				
				if (en.getValueAsString() != null)
					essentialACRs.add(new ACR(en.getValueAsString()));
				
				if (en.getValuesAsListOfStrings() != null) {
					for (String v: en.getValuesAsListOfStrings())
						essentialACRs.add(new ACR(v));
				}
			} else {
				voluntaryACRs = new ArrayList<>();
				
				if (en.getValueAsString() != null)
					voluntaryACRs.add(new ACR(en.getValueAsString()));
				
				if (en.getValuesAsListOfStrings() != null) {
					
					for (String v: en.getValuesAsListOfStrings())
						voluntaryACRs.add(new ACR(v));
				}
			}
		}
		
		if (acrValues != null) {
			
			if (voluntaryACRs == null)
				voluntaryACRs = new ArrayList<>();
			
			voluntaryACRs.addAll(acrValues);
		}
		
		return new ACRRequest(essentialACRs, voluntaryACRs);
	}
}