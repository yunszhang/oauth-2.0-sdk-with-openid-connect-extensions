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

package com.nimbusds.openid.connect.sdk.federation.policy.factories;


import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.federation.policy.MetadataPolicy;
import com.nimbusds.openid.connect.sdk.federation.policy.MetadataPolicyEntry;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.ValueOperation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;


public class DefaultRPMetadataPolicyFactoryTest extends TestCase {
	
	
	public void testTransform()
		throws PolicyFormulationException, PolicyViolationException {
		
		OIDCClientMetadata initialMetadata = new OIDCClientMetadata();
		initialMetadata.setRedirectionURI(URI.create("https://rp.example.com/cb"));
		initialMetadata.setCustomField("unsupported-param", "xyz"); // to be removed
		
		Set<String> initialParamNames = initialMetadata.toJSONObject().keySet();
		
		OIDCClientMetadata registeredMetadata = new OIDCClientMetadata(initialMetadata);
		registeredMetadata.applyDefaults();
		
		ClientID clientID = new ClientID("https://rp.example.com");
		OIDCClientInformation clientInfo = new OIDCClientInformation(
			clientID,
			null,
			registeredMetadata,
			new Secret(),
			null,
			null);
		
		Set<String> finalParamNames = clientInfo.toJSONObject().keySet();
		
		Set<String> diffParamNames = new HashSet<>(finalParamNames);
		diffParamNames.removeAll(initialParamNames);
		
		MetadataPolicy policy = new DefaultRPMetadataPolicyFactory().create(initialMetadata, clientInfo);
		
		for (MetadataPolicyEntry en: policy.entrySet()) {
			assertTrue(diffParamNames.contains(en.getParameterName()));
			List<PolicyOperation> opList = en.getPolicyOperations();
			PolicyOperation op = opList.get(0);
			assertTrue(op instanceof ValueOperation);
			assertEquals(1, opList.size());
		}
		
		JSONObject out = policy.apply(initialMetadata.toJSONObject());
		assertEquals(clientInfo.toJSONObject(), out);
	}
}
