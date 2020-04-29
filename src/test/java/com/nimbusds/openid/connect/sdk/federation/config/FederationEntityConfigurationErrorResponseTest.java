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

package com.nimbusds.openid.connect.sdk.federation.config;


import junit.framework.TestCase;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.federation.config.FederationEntityConfigurationErrorResponse;
import com.nimbusds.openid.connect.sdk.federation.config.FederationEntityConfigurationResponse;


public class FederationEntityConfigurationErrorResponseTest extends TestCase {
	
	
	public void testWithErrorCode()
		throws Exception {
		
		ErrorObject errorObject = OAuth2Error.SERVER_ERROR;
		
		FederationEntityConfigurationErrorResponse response = new FederationEntityConfigurationErrorResponse(errorObject);
		assertFalse(response.indicatesSuccess());
		assertEquals(errorObject, response.getErrorObject());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(500, httpResponse.getStatusCode());
		assertEquals(ContentType.APPLICATION_JSON, httpResponse.getEntityContentType());
		assertEquals(errorObject.toJSONObject(), httpResponse.getContentAsJSONObject());
		
		response = FederationEntityConfigurationResponse.parse(httpResponse).toErrorResponse();
		assertFalse(response.indicatesSuccess());
		assertEquals(errorObject, response.getErrorObject());
	}
	
	
	public void testNoErrorCode()
		throws Exception {
		
		ErrorObject errorObject = new ErrorObject(null);
		
		FederationEntityConfigurationErrorResponse response = new FederationEntityConfigurationErrorResponse(new ErrorObject(null));
		assertFalse(response.indicatesSuccess());
		assertEquals(errorObject, response.getErrorObject());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(400, httpResponse.getStatusCode());
		assertNull(httpResponse.getEntityContentType());
		assertNull(httpResponse.getContent());
		
		response = FederationEntityConfigurationResponse.parse(httpResponse).toErrorResponse();
		assertFalse(response.indicatesSuccess());
		assertEquals(errorObject, response.getErrorObject());
	}
}
