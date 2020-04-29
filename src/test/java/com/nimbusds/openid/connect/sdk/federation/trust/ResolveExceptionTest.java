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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ErrorObject;


public class ResolveExceptionTest extends TestCase {
	
	
	public void testMessageConstructor() {
		
		String msg = "Message";
		ResolveException e = new ResolveException(msg);
		assertEquals(msg, e.getMessage());
		assertTrue(e.getCauses().isEmpty());
	}
	
	public void testErrorObjectConstructor() {
		
		String msg = "Message";
		ErrorObject errorObject = new ErrorObject("invalid_request");
		ResolveException e = new ResolveException(msg, errorObject);
		assertEquals(msg, e.getMessage());
		assertEquals(errorObject, e.getErrorObject());
	}
	
	public void testMessageWithCauseConstructor() {
		
		String msg = "Message";
		Throwable cause = new IOException("HTTP timeout");
		ResolveException e = new ResolveException(msg, cause);
		assertEquals(msg, e.getMessage());
		assertEquals(cause, e.getCause());
		assertEquals(Collections.singletonList(cause), e.getCauses());
	}
	
	public void testMessageWithMultipleCausesConstructor() {
		
		String msg = "Message";
		Throwable cause1 = new IOException("HTTP timeout");
		Throwable cause2 = new IOException("Invalid host");
		List<Throwable> causes = Arrays.asList(cause1, cause2);
		ResolveException e = new ResolveException(msg, causes);
		assertEquals(msg, e.getMessage());
		assertNull(e.getCause());
		assertEquals(causes, e.getCauses());
	}
}
