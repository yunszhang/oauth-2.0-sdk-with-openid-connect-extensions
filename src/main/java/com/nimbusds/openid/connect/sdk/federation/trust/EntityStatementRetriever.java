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
import com.nimbusds.openid.connect.sdk.federation.entities.FederationEntityMetadata;


/**
 * Entity statement retriever for resolving trust chains.
 */
class EntityStatementRetriever {
	
	
	private final int httpConnectTimeoutMs;
	
	
	private final int httpReadTimeoutMs;
	
	
	static final int DEFAULT_HTTP_CONNECT_TIMEOUT_MS = 1000;
	
	
	static final int DEFAULT_HTTP_READ_TIMEOUT_MS = 1000;
	
	
	EntityStatementRetriever() {
		this(DEFAULT_HTTP_CONNECT_TIMEOUT_MS, DEFAULT_HTTP_READ_TIMEOUT_MS);
	}
	
	
	EntityStatementRetriever(final int httpConnectTimeoutMs,
				 final int httpReadTimeoutMs) {
		this.httpConnectTimeoutMs = httpConnectTimeoutMs;
		this.httpReadTimeoutMs = httpReadTimeoutMs;
	}
	
	
	public int getHTTPConnectTimeout() {
		return httpConnectTimeoutMs;
	}
	
	
	public int getHTTPReadTimeout() {
		return httpReadTimeoutMs;
	}
	
	
	void applyTimeouts(final HTTPRequest httpRequest) {
		httpRequest.setConnectTimeout(httpConnectTimeoutMs);
		httpRequest.setReadTimeout(httpReadTimeoutMs);
	}
	
	
	EntityStatement fetchSelfIssuedEntityStatement(final EntityID target)
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
			throw new ResolveException("Entity configuration error response from " + target + ": " + errorObject.getCode(), errorObject);
		}
		
		return response.toSuccessResponse().getEntityStatement();
	}
	
	
	URI resolveFederationAPIURI(final EntityID entityID)
		throws ResolveException {
		
		EntityStatement entityStatement = fetchSelfIssuedEntityStatement(entityID);
		
		FederationEntityMetadata metadata = entityStatement.getClaimsSet().getFederationEntityMetadata();
		
		if (metadata == null) {
			return null;
		}
		
		return metadata.getFederationAPIEndpointURI();
	}
	
	
	EntityStatement fetchEntityStatement(final URI federationAPIEndpoint, final EntityID issuer, final EntityID subject)
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
			throw new ResolveException("Entity statement error response from " + issuer + " at " + federationAPIEndpoint + ": " + errorObject.getCode(), errorObject);
		}
		
		return response.toSuccessResponse().getEntityStatement();
	}
}
