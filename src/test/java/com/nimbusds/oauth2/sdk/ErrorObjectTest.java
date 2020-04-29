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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertNotEquals;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;


public class ErrorObjectTest extends TestCase {


	public void testConstructor1() {

		ErrorObject eo = new ErrorObject("access_denied");

		assertEquals("access_denied", eo.getCode());
		assertNull(eo.getDescription());
		assertNull(eo.getURI());
		assertEquals(0, eo.getHTTPStatusCode());

		assertEquals("access_denied", (String)eo.toJSONObject().get("error"));
		assertEquals(1, eo.toJSONObject().size());
		
		assertEquals("access_denied", MultivaluedMapUtils.getFirstValue(eo.toParameters(), "error"));
		assertEquals(1, eo.toParameters().size());
	}


	public void testConstructor2() {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied");

		assertEquals("access_denied", eo.getCode());
		assertEquals("Access denied", eo.getDescription());
		assertNull(eo.getURI());
		assertEquals(0, eo.getHTTPStatusCode());

		assertEquals("access_denied", (String)eo.toJSONObject().get("error"));
		assertEquals("Access denied", (String)eo.toJSONObject().get("error_description"));
		assertEquals(2, eo.toJSONObject().size());
		
		assertEquals("access_denied", MultivaluedMapUtils.getFirstValue(eo.toParameters(), "error"));
		assertEquals("Access denied", MultivaluedMapUtils.getFirstValue(eo.toParameters(), "error_description"));
		assertEquals(2, eo.toParameters().size());
	}


	public void testConstructor3() {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied", 403);

		assertEquals("access_denied", eo.getCode());
		assertEquals("Access denied", eo.getDescription());
		assertNull(eo.getURI());
		assertEquals(403, eo.getHTTPStatusCode());

		assertEquals("access_denied", (String)eo.toJSONObject().get("error"));
		assertEquals("Access denied", (String)eo.toJSONObject().get("error_description"));
		assertEquals(2, eo.toJSONObject().size());
	}


	public void testConstructor4()
		throws Exception {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied", 403, new URI("https://c2id.com/errors/access_denied"));

		assertEquals("access_denied", eo.getCode());
		assertEquals("Access denied", eo.getDescription());
		assertEquals(new URI("https://c2id.com/errors/access_denied"), eo.getURI());
		assertEquals(403, eo.getHTTPStatusCode());

		assertEquals("access_denied", (String)eo.toJSONObject().get("error"));
		assertEquals("Access denied", (String)eo.toJSONObject().get("error_description"));
		assertEquals("https://c2id.com/errors/access_denied", (String)eo.toJSONObject().get("error_uri"));
		assertEquals(3, eo.toJSONObject().size());
		
		assertEquals("access_denied", MultivaluedMapUtils.getFirstValue(eo.toParameters(), "error"));
		assertEquals("Access denied", MultivaluedMapUtils.getFirstValue(eo.toParameters(), "error_description"));
		assertEquals("https://c2id.com/errors/access_denied", MultivaluedMapUtils.getFirstValue(eo.toParameters(), "error_uri"));
		assertEquals(3, eo.toParameters().size());
	}


	public void testParseFull_httpRequest() {

		HTTPResponse httpResponse = new HTTPResponse(403);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("error", "access_denied");
		jsonObject.put("error_description", "Access denied");
		jsonObject.put("error_uri", "https://c2id.com/errors/access_denied");

		httpResponse.setContent(jsonObject.toJSONString());

		ErrorObject errorObject = ErrorObject.parse(httpResponse);

		assertEquals(403, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertEquals("Access denied", errorObject.getDescription());
		assertEquals("https://c2id.com/errors/access_denied", errorObject.getURI().toString());
	}


	public void testParseWithOmittedURI_httpRequest() {

		HTTPResponse httpResponse = new HTTPResponse(403);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("error", "access_denied");
		jsonObject.put("error_description", "Access denied");

		httpResponse.setContent(jsonObject.toJSONString());

		ErrorObject errorObject = ErrorObject.parse(httpResponse);

		assertEquals(403, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertEquals("Access denied", errorObject.getDescription());
		assertNull(errorObject.getURI());
	}


	public void testParseWithCodeOnly_httpRequest() {

		HTTPResponse httpResponse = new HTTPResponse(403);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("error", "access_denied");

		httpResponse.setContent(jsonObject.toJSONString());

		ErrorObject errorObject = ErrorObject.parse(httpResponse);

		assertEquals(403, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertNull(errorObject.getDescription());
		assertNull(errorObject.getURI());
	}
	
	
	public void testParseNone_httpRequest() {
		
		HTTPResponse httpResponse = new HTTPResponse(403);
		
		ErrorObject errorObject = ErrorObject.parse(httpResponse);
		
		assertEquals(403, errorObject.getHTTPStatusCode());
		assertNull(errorObject.getCode());
		assertNull(errorObject.getDescription());
		assertNull(errorObject.getURI());
	}


	public void testParseFull_params() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("error", Collections.singletonList("access_denied"));
		params.put("error_description", Collections.singletonList("Access denied"));
		params.put("error_uri", Collections.singletonList("https://c2id.com/errors/access_denied"));
		

		ErrorObject errorObject = ErrorObject.parse(params);

		assertEquals(0, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertEquals("Access denied", errorObject.getDescription());
		assertEquals("https://c2id.com/errors/access_denied", errorObject.getURI().toString());
	}


	public void testParseWithOmittedURI_params() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("error", Collections.singletonList("access_denied"));
		params.put("error_description", Collections.singletonList("Access denied"));

		ErrorObject errorObject = ErrorObject.parse(params);

		assertEquals(0, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertEquals("Access denied", errorObject.getDescription());
		assertNull(errorObject.getURI());
	}


	public void testParseWithCodeOnly_params() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("error", Collections.singletonList("access_denied"));

		ErrorObject errorObject = ErrorObject.parse(params);

		assertEquals(0, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertNull(errorObject.getDescription());
		assertNull(errorObject.getURI());
	}


	public void testParseNone_params() {
		
		ErrorObject errorObject = ErrorObject.parse(new HashMap<String, List<String>>());

		assertEquals(0, errorObject.getHTTPStatusCode());
		assertNull(errorObject.getCode());
		assertNull(errorObject.getDescription());
		assertNull(errorObject.getURI());
	}


	public void testEquality() {
		
		assertEquals(new ErrorObject("invalid_grant", null, 400), OAuth2Error.INVALID_GRANT);
		assertEquals(new ErrorObject("invalid_grant", null, 0), OAuth2Error.INVALID_GRANT);
		assertEquals(new ErrorObject(null, null, 0), new ErrorObject(null, null, 0));
	}


	public void testInequality() {
		
		assertNotEquals(new ErrorObject("bad_request", null, 400), OAuth2Error.INVALID_GRANT);
		assertNotEquals(new ErrorObject("bad_request", null, 0), OAuth2Error.INVALID_GRANT);
	}


	public void testSetDescription() {

		assertEquals("new description", new ErrorObject("bad_request", "old description").setDescription("new description").getDescription());
	}


	public void testAppendDescription() {

		assertEquals("a b", new ErrorObject("bad_request", "a").appendDescription(" b").getDescription());
	}


	public void testSetHTTPStatusCode() {

		assertEquals(440, new ErrorObject("code", "description", 400).setHTTPStatusCode(440).getHTTPStatusCode());
	}
}
