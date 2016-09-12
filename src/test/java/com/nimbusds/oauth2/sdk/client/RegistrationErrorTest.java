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

package com.nimbusds.oauth2.sdk.client;


import junit.framework.TestCase;


/**
 * Tests the registration error constants.
 */
public class RegistrationErrorTest extends TestCase {


	public void testConstants() {

		// http://tools.ietf.org/html/draft-ietf-oauth-dyn-reg-17#section-4.2

		assertEquals("invalid_redirect_uri", RegistrationError.INVALID_REDIRECT_URI.getCode());
		assertEquals("invalid_client_metadata", RegistrationError.INVALID_CLIENT_METADATA.getCode());
		assertEquals("invalid_software_statement", RegistrationError.INVALID_SOFTWARE_STATEMENT.getCode());
		assertEquals("unapproved_software_statement", RegistrationError.UNAPPROVED_SOFTWARE_STATEMENT.getCode());
	}
}
