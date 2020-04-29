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

package com.nimbusds.openid.connect.sdk.federation.api;


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Federation API request.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 6.
 * </ul>
 */
public abstract class FederationAPIRequest extends AbstractRequest {
	
	
	/**
	 * The requested operation.
	 */
	private final OperationType operationType;
	
	
	/**
	 * Creates a new federation API request.
	 *
	 * @param endpoint      The federation API endpoint. Must not be
	 *                      {@code null}.
	 * @param operationType The requested operation type. Must not be
	 *                      {@code null}.
	 */
	public FederationAPIRequest(final URI endpoint, final OperationType operationType) {
		super(endpoint);
		if (operationType == null) {
			throw new IllegalArgumentException("The operation type must not be null");
		}
		this.operationType = operationType;
	}
	
	
	/**
	 * Returns the requested operation type.
	 *
	 * @return The operation type.
	 */
	public OperationType getOperationType() {
		return operationType;
	}
	
	
	/**
	 * Returns the request query parameters.
	 *
	 * @return The request query parameters.
	 */
	public abstract Map<String, List<String>> toParameters();
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
		
		URL url;
		try {
			url = getEndpointURI().toURL();
		} catch (IllegalArgumentException | MalformedURLException e) {
			throw new SerializeException(e.getMessage(), e);
		}
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, url);
		httpRequest.setQuery(URLUtils.serializeParameters(toParameters()));
		return httpRequest;
	}
}
