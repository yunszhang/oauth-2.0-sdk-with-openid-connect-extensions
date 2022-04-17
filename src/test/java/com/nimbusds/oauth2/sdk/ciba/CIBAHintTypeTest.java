/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk.ciba;


import junit.framework.TestCase;


public class CIBAHintTypeTest extends TestCase {


	public void testEnums() {
		
		assertEquals("login_hint_token", CIBAHintType.LOGIN_HINT_TOKEN.toString());
		assertEquals("id_token_hint", CIBAHintType.ID_TOKEN_HINT.toString());
		assertEquals("login_hint", CIBAHintType.LOGIN_HINT.toString());
		
		assertEquals(3, CIBAHintType.values().length);
	}
}
