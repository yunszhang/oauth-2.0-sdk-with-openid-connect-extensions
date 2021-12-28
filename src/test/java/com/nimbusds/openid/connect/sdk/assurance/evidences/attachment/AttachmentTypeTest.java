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

package com.nimbusds.openid.connect.sdk.assurance.evidences.attachment;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;


public class AttachmentTypeTest extends TestCase {


	public void testEnum() {
		
		assertEquals("EMBEDDED", AttachmentType.EMBEDDED.name());
		assertEquals("embedded", AttachmentType.EMBEDDED.toString());
		
		assertEquals("EXTERNAL", AttachmentType.EXTERNAL.name());
		assertEquals("external", AttachmentType.EXTERNAL.toString());
		
		assertEquals(2, AttachmentType.values().length);
	}
	
	
	public void testParse()
		throws ParseException {
		
		assertEquals(AttachmentType.EMBEDDED, AttachmentType.parse("embedded"));
		assertEquals(AttachmentType.EMBEDDED, AttachmentType.parse("EMBEDDED"));
		
		assertEquals(AttachmentType.EXTERNAL, AttachmentType.parse("external"));
		assertEquals(AttachmentType.EXTERNAL, AttachmentType.parse("EXTERNAL"));
	}
	
	
	public void testParse_null() {
		
		try {
			AttachmentType.parse(null);
			fail();
		} catch (ParseException e) {
			assertEquals("Null or blank attachment type", e.getMessage());
		}
	}
	
	
	public void testParse_empty() {
		
		try {
			AttachmentType.parse("");
			fail();
		} catch (ParseException e) {
			assertEquals("Null or blank attachment type", e.getMessage());
		}
	}
	
	
	public void testParse_blank() {
		
		try {
			AttachmentType.parse(" ");
			fail();
		} catch (ParseException e) {
			assertEquals("Null or blank attachment type", e.getMessage());
		}
	}
	
	
	public void testParse_invalid() {
		
		try {
			AttachmentType.parse("xxx");
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid attachment type: xxx", e.getMessage());
		}
	}
}
