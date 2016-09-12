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


import java.net.URI;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;


/**
 * Request message, serialises to an HTTP request.
 */
public interface Request extends Message {


	/**
	 * Gets the URI of the endpoint (HTTP or HTTPS) for which the request 
	 * is intended.
	 * 
	 * @return The endpoint URI, {@code null} if not specified.
	 */
	URI getEndpointURI();
	
	
	/**
	 * Returns the matching HTTP request.
	 *
	 * @return The HTTP request.
	 */
	HTTPRequest toHTTPRequest();
}
