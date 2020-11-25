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

package com.nimbusds.openid.connect.sdk.rp.statement;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.client.RegistrationError;


public class InvalidSoftwareStatementExceptionTest {


	@Test
	public void minimalConstructor_withMessage() {
		
		String message = "Missing required software statement";
		InvalidSoftwareStatementException e = new InvalidSoftwareStatementException(message);
		assertEquals(message, e.getMessage());
		assertEquals(RegistrationError.INVALID_SOFTWARE_STATEMENT.getCode(), e.getErrorObject().getCode());
		assertEquals(message, e.getErrorObject().getDescription());
		assertNull(e.getErrorObject().getURI());
	}


	@Test
	public void minimalConstructor_nullMessage() {
		
		InvalidSoftwareStatementException e = new InvalidSoftwareStatementException(null);
		assertNull(e.getMessage());
		assertEquals(RegistrationError.INVALID_SOFTWARE_STATEMENT.getCode(), e.getErrorObject().getCode());
		assertEquals(RegistrationError.INVALID_SOFTWARE_STATEMENT.getDescription(), e.getErrorObject().getDescription());
		assertNull(e.getErrorObject().getURI());
	}


	@Test
	public void causeConstructor_withMessage() {
		
		String message = "Missing required software statement";
		Throwable cause = new BadJOSEException("Invalid signature");
		InvalidSoftwareStatementException e = new InvalidSoftwareStatementException(message, cause);
		assertEquals(message, e.getMessage());
		assertEquals(cause, e.getCause());
		assertEquals(RegistrationError.INVALID_SOFTWARE_STATEMENT.getCode(), e.getErrorObject().getCode());
		assertEquals(message, e.getErrorObject().getDescription());
		assertNull(e.getErrorObject().getURI());
	}


	@Test
	public void causeConstructor_nullMessage() {
		
		Throwable cause = new BadJOSEException("Invalid signature");
		InvalidSoftwareStatementException e = new InvalidSoftwareStatementException(null, cause);
		assertNull(e.getMessage());
		assertEquals(cause, e.getCause());
		assertEquals(RegistrationError.INVALID_SOFTWARE_STATEMENT.getCode(), e.getErrorObject().getCode());
		assertEquals(RegistrationError.INVALID_SOFTWARE_STATEMENT.getDescription(), e.getErrorObject().getDescription());
		assertNull(e.getErrorObject().getURI());
	}
}
