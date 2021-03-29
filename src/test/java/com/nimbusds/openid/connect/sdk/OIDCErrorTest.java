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

package com.nimbusds.openid.connect.sdk;


import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ErrorObject;


public class OIDCErrorTest extends TestCase {
	

	public void testCodes() throws IllegalAccessException {
		
		assertEquals("interaction_required", OIDCError.INTERACTION_REQUIRED.getCode());
		assertEquals("login_required", OIDCError.LOGIN_REQUIRED.getCode());
		assertEquals("account_selection_required", OIDCError.ACCOUNT_SELECTION_REQUIRED.getCode());
		assertEquals("consent_required", OIDCError.CONSENT_REQUIRED.getCode());
		assertEquals("unmet_authentication_requirements", OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS.getCode());
		assertEquals("registration_not_supported", OIDCError.REGISTRATION_NOT_SUPPORTED.getCode());
		
		assertEquals(6, getErrorObjectConstants().size());
	}
	
	
	public void testErrorCodeStringConstantsAreProvided() throws IllegalAccessException {
		Set<String> errorCodeStringConstants = getErrorCodeStringConstants();
		Set<ErrorObject> errorObjectConstants = getErrorObjectConstants();
		for (ErrorObject eo : errorObjectConstants) {
			assertTrue(errorCodeStringConstants.contains(eo.getCode()));
		}
	}
	
	
	private Set<String> getErrorCodeStringConstants() throws IllegalAccessException {
		Field[] oidcErrorFields = OIDCError.class.getDeclaredFields();
		Set<String> errorCodeStringConstants = new HashSet<>();
		for (Field field : oidcErrorFields) {
			if (field.getType().equals(String.class)
				&& Modifier.isPublic(field.getModifiers())
				&& Modifier.isFinal(field.getModifiers())
				&& Modifier.isStatic(field.getModifiers())) {
				errorCodeStringConstants.add((String) field.get(this));
			}
		}
		return errorCodeStringConstants;
	}
	
	
	private Set<ErrorObject> getErrorObjectConstants() throws IllegalAccessException {
		Field[] oidcErrorFields = OIDCError.class.getDeclaredFields();
		Set<ErrorObject> errorObjectConstants = new HashSet<>();
		for (Field field : oidcErrorFields) {
			if (field.getType().equals(ErrorObject.class)) {
				errorObjectConstants.add((ErrorObject) field.get(this));
			}
		}
		return errorObjectConstants;
	}
}
