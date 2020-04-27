/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.trust;


import java.io.IOException;
import java.net.URI;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.federation.api.FetchEntityStatementRequest;
import com.nimbusds.openid.connect.sdk.federation.api.FetchEntityStatementResponse;
import com.nimbusds.openid.connect.sdk.federation.config.FederationEntityConfigurationRequest;
import com.nimbusds.openid.connect.sdk.federation.config.FederationEntityConfigurationResponse;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;


/**
 * Entity statement retriever for resolving trust chains.
 */
class DefaultEntityStatementRetriever implements EntityStatementRetriever {
	
	
	/**
	 * The HTTP connect timeout in milliseconds.
	 */
	private final int httpConnectTimeoutMs;
	
	
	/**
	 * The HTTP read timeout in milliseconds.
	 */
	private final int httpReadTimeoutMs;
	
	
	/**
	 * The default HTTP connect timeout in milliseconds.
	 */
	static final int DEFAULT_HTTP_CONNECT_TIMEOUT_MS = 1000;
	
	
	/**
	 * The default HTTP read timeout in milliseconds.
	 */
	static final int DEFAULT_HTTP_READ_TIMEOUT_MS = 1000;
	
	
	/**
	 * Creates a new entity statement retriever using the default HTTP
	 * timeout settings.
	 */
	DefaultEntityStatementRetriever() {
		this(DEFAULT_HTTP_CONNECT_TIMEOUT_MS, DEFAULT_HTTP_READ_TIMEOUT_MS);
	}
	
	
	/**
	 * Creates a new entity statement retriever.
	 *
	 * @param httpConnectTimeoutMs The HTTP connect timeout in
	 *                             milliseconds, zero means timeout
	 *                             determined by the underlying HTTP client.
	 * @param httpReadTimeoutMs    The HTTP read timeout in milliseconds,
	 *                             zero means timeout determined by the
	 *                             underlying HTTP client.
	 */
	DefaultEntityStatementRetriever(final int httpConnectTimeoutMs,
					final int httpReadTimeoutMs) {
		this.httpConnectTimeoutMs = httpConnectTimeoutMs;
		this.httpReadTimeoutMs = httpReadTimeoutMs;
	}
	
	
	/**
	 * Returns the configured HTTP connect timeout.
	 *
	 * @return The configured HTTP connect timeout in milliseconds, zero
	 *         means timeout determined by the underlying HTTP client.
	 */
	int getHTTPConnectTimeout() {
		return httpConnectTimeoutMs;
	}
	
	
	/**
	 * Returns the configured HTTP read timeout.
	 *
	 * @return The configured HTTP read timeout in milliseconds, zero
	 *         means timeout determined by the underlying HTTP client.
	 */
	int getHTTPReadTimeout() {
		return httpReadTimeoutMs;
	}
	
	
	void applyTimeouts(final HTTPRequest httpRequest) {
		httpRequest.setConnectTimeout(httpConnectTimeoutMs);
		httpRequest.setReadTimeout(httpReadTimeoutMs);
	}
	
	
	@Override
	public EntityStatement fetchSelfIssuedEntityStatement(final EntityID target)
		throws ResolveException {
		
		FederationEntityConfigurationRequest request = new FederationEntityConfigurationRequest(target);
		HTTPRequest httpRequest = request.toHTTPRequest();
		applyTimeouts(httpRequest);
		
		HTTPResponse httpResponse;
		try {
			httpResponse = httpRequest.send();
		} catch (IOException e) {
			throw new ResolveException("Couldn't retrieve entity configuration for " + target + ": " + e.getMessage(), e);
		}
		
		FederationEntityConfigurationResponse response;
		
		try {
			response = FederationEntityConfigurationResponse.parse(httpResponse);
		} catch (ParseException e) {
			throw new ResolveException("Error parsing entity configuration response from " + target + ": " + e.getMessage(), e);
		}
		
		if (! response.indicatesSuccess()) {
			ErrorObject errorObject = response.toErrorResponse().getErrorObject();
			throw new ResolveException("Entity configuration error response from " + target + ": " +
				errorObject.getHTTPStatusCode() +
				(errorObject.getCode() != null ? " " + errorObject.getCode() : ""),
				errorObject);
		}
		
		return response.toSuccessResponse().getEntityStatement();
	}
	
	
	@Override
	public EntityStatement fetchEntityStatement(final URI federationAPIEndpoint, final EntityID issuer, final EntityID subject)
		throws ResolveException {
		
		FetchEntityStatementRequest request = new FetchEntityStatementRequest(federationAPIEndpoint, issuer, subject, null);
		HTTPRequest httpRequest = request.toHTTPRequest();
		applyTimeouts(httpRequest);
		
		HTTPResponse httpResponse;
		try {
			httpResponse = httpRequest.send();
		} catch (IOException e) {
			throw new ResolveException("Couldn't fetch entity statement from " + issuer + " at " + federationAPIEndpoint + ": " + e.getMessage(), e);
		}
		
		FetchEntityStatementResponse response;
		try {
			response = FetchEntityStatementResponse.parse(httpResponse);
		} catch (ParseException e) {
			throw new ResolveException("Error parsing entity statement response from " + issuer + " at " + federationAPIEndpoint + ": " + e.getMessage(), e);
		}
		
		if (! response.indicatesSuccess()) {
			ErrorObject errorObject = response.toErrorResponse().getErrorObject();
			throw new ResolveException("Entity statement error response from " + issuer + " at " + federationAPIEndpoint + ": " +
				errorObject.getHTTPStatusCode() +
				(errorObject.getCode() != null ? " " + errorObject.getCode() : ""),
				errorObject);
		}
		
		return response.toSuccessResponse().getEntityStatement();
	}
}
