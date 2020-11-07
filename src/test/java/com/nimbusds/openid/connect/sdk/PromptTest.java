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


import java.util.Arrays;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;


public class PromptTest extends TestCase {
	
	
	public void testPromptTypeValues() throws ParseException {
		
		List<String> names = Arrays.asList("login", "consent", "select_account", "none", "create");
		
		for (Prompt.Type type: Prompt.Type.values()) {
			assertEquals(type, Prompt.Type.valueOf(type.name()));
			assertEquals(type, Prompt.Type.parse(type.toString()));
			assertTrue(names.contains(type.toString()));
		}
	}

	
	public void testRun()
		throws Exception {
		
		Prompt p = new Prompt();
		p.add(Prompt.Type.CONSENT);
		p.add(Prompt.Type.LOGIN);
		
		assertTrue(p.isValid());
		
		String s = p.toString();
		
		p = Prompt.parse(s);
		
		assertTrue(p.contains(Prompt.Type.CONSENT));
		assertTrue(p.contains(Prompt.Type.LOGIN));
		assertEquals(2, p.size());
	}


	public void testVarargConstructor() {

		Prompt p = new Prompt(Prompt.Type.LOGIN, Prompt.Type.CONSENT, Prompt.Type.SELECT_ACCOUNT);

		assertTrue(p.contains(Prompt.Type.LOGIN));
		assertTrue(p.contains(Prompt.Type.CONSENT));
		assertTrue(p.contains(Prompt.Type.SELECT_ACCOUNT));

		assertEquals(3, p.size());

		assertTrue(p.isValid());
	}


	public void testVarargStringConstructor() {

		Prompt p = new Prompt("login", "consent", "select_account");

		assertTrue(p.contains(Prompt.Type.LOGIN));
		assertTrue(p.contains(Prompt.Type.CONSENT));
		assertTrue(p.contains(Prompt.Type.SELECT_ACCOUNT));

		assertEquals(3, p.size());

		assertTrue(p.isValid());
	}
	
	
	public void testListSerializationAndParsing()
		throws Exception {
		
		Prompt p = new Prompt();
		p.add(Prompt.Type.CONSENT);
		p.add(Prompt.Type.LOGIN);
		
		assertTrue(p.isValid());
		
		List<String> list = p.toStringList();
		
		assertTrue(list.contains("consent"));
		assertTrue(list.contains("login"));
		assertEquals(2, list.size());
		
		p = Prompt.parse(list);
		
		assertTrue(p.contains(Prompt.Type.CONSENT));
		assertTrue(p.contains(Prompt.Type.LOGIN));
		assertEquals(2, p.size());
	}
	
	
	public void testParsePromptCreate() throws ParseException {
		
		assertEquals("create", Prompt.Type.CREATE.toString());
		
		assertEquals(Prompt.Type.CREATE, Prompt.Type.parse("create"));
		
		Prompt prompt = Prompt.parse("create");
		assertEquals(new Prompt(Prompt.Type.CREATE), prompt);
	}
	
	
	public void testParseInvalidPrompt() {
		
		try {
			Prompt.parse("none login");
			fail("Failed to raise exception on none login");
		} catch (ParseException ex) {
			// ok
		}
		
		try {
			Prompt.parse("none consent");
			fail("Failed to raise exception on none consent");
		} catch (ParseException ex) {
			// ok
		}
		
		try {
			Prompt.parse("none select_account");
			fail("Failed to raise exception on none select_account");
		} catch (ParseException ex) {
			// ok
		}
		
		try {
			Prompt.parse("none login consent select_account");
			fail("Failed to raise exception on none consent select_account");
		} catch (ParseException ex) {
			// ok
		}
	}
}
