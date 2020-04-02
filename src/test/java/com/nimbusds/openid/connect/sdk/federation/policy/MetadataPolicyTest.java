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

package com.nimbusds.openid.connect.sdk.federation.policy;


import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.*;


public class MetadataPolicyTest extends TestCase {
	
	
	public void testExample() throws ParseException, PolicyViolationException {
		
		String json = "{"+
			"\"scopes\":{"+
			"\"subset_of\":[\"openid\",\"eduperson\",\"phone\"],"+
			"\"superset_of\":[\"openid\"],"+
			"\"default\":[\"openid\",\"eduperson\"]},"+
			"\"id_token_signed_response_alg\":{"+
			"\"one_of\":[\"ES256\",\"ES384\",\"ES512\"]},"+
			"\"contacts\":{"+
			"\"add\":\"helpdesk@federation.example.org\"},"+
			"\"application_type\":{\"value\":\"web\"}"+
			"}";
		
		MetadataPolicy metadataPolicy = MetadataPolicy.parse(json);
		
		Iterator<MetadataPolicyEntry> it = metadataPolicy.entrySet().iterator();
		
		// scopes
		MetadataPolicyEntry en = it.next();
		assertEquals("scopes", en.getParameterName());
		List<PolicyOperation> ops = en.getPolicyOperations();
		
		SubsetOfOperation subsetOfOperation = (SubsetOfOperation) ops.get(0);
		assertEquals(Arrays.asList("openid", "eduperson", "phone"), subsetOfOperation.getStringListConfiguration());
		
		SupersetOfOperation supersetOfOperation = (SupersetOfOperation) ops.get(1);
		assertEquals(Collections.singletonList("openid"), supersetOfOperation.getStringListConfiguration());
		
		DefaultOperation defaultOperation = (DefaultOperation) ops.get(2);
		assertEquals(Arrays.asList("openid", "eduperson"), defaultOperation.getStringListConfiguration());
		
		assertEquals(3, ops.size());
		
		// id_token_signed_response_alg
		en = it.next();
		assertEquals("id_token_signed_response_alg", en.getParameterName());
		ops = en.getPolicyOperations();
		
		OneOfOperation oneOfOperation = (OneOfOperation) ops.get(0);
		assertEquals(Arrays.asList("ES256", "ES384", "ES512"), oneOfOperation.getStringListConfiguration());
		
		assertEquals(1, ops.size());
		
		// contacts
		en = it.next();
		assertEquals("contacts", en.getParameterName());
		ops = en.getPolicyOperations();
		
		AddOperation addOperation = (AddOperation) ops.get(0);
		assertEquals("helpdesk@federation.example.org", addOperation.getStringConfiguration());
		
		assertEquals(1, ops.size());
		
		// application_type
		en = it.next();
		assertEquals("application_type", en.getParameterName());
		ops = en.getPolicyOperations();
		
		ValueOperation valueOperation = (ValueOperation) ops.get(0);
		assertEquals("web", valueOperation.getStringConfiguration());
		
		assertEquals(1, ops.size());
		
		// Back to JSON object
		assertEquals(json, metadataPolicy.toJSONString());
	}
}
