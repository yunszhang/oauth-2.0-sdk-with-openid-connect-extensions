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

package com.nimbusds.openid.connect.sdk.op;


import java.net.URI;
import java.util.*;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import junit.framework.TestCase;


/**
 * Tests the ACR request class.
 */
public class ACRRequestTest extends TestCase {
	
	
	public void testConstructAndGet() {
		
		List<ACR> essentialACRs = new ArrayList<>();
		essentialACRs.add(new ACR("1"));
		
		List<ACR> voluntaryACRs = new ArrayList<>();
		voluntaryACRs.add(new ACR("2"));
		
		ACRRequest req = new ACRRequest(essentialACRs, voluntaryACRs);
		
		assertEquals(essentialACRs, req.getEssentialACRs());
		assertEquals(voluntaryACRs, req.getVoluntaryACRs());
		
		assertEquals(1, req.getEssentialACRs().size());
		assertEquals(1, req.getVoluntaryACRs().size());
	}
	
	
	public void testConstructAndGetNull() {
		
		ACRRequest req = new ACRRequest(null, null);
		
		assertNull(req.getEssentialACRs());
		assertNull(req.getVoluntaryACRs());
	}
	
	
	public void testResolveNone()
		throws Exception {
		
		AuthenticationRequest authRequest = new AuthenticationRequest(
			new URI("https://c2id.com/login"),
			new ResponseType("code"),
			Scope.parse("openid profile"),
			new ClientID("abc"),
			new URI("https://example.com/in"),
			new State(),
			new Nonce());
		
		ACRRequest acrRequest = ACRRequest.resolve(authRequest);
		
		assertNull(acrRequest.getEssentialACRs());
		assertNull(acrRequest.getVoluntaryACRs());
		
		assertTrue(acrRequest.isEmpty());
	}
	
	
	public void testResolveTopLevelACRRequest()
		throws Exception {

		List<ACR> acrValues = new ArrayList<>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));
		
		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid", "profile"),
			new ClientID("123"),
			new URI("https://example.com/in")).
			acrValues(acrValues).
			build();
		
		ACRRequest acrRequest = ACRRequest.resolve(authRequest);
		
		assertNull(acrRequest.getEssentialACRs());
		
		List<ACR> voluntaryACRs = acrRequest.getVoluntaryACRs();
		
		assertTrue(voluntaryACRs.contains(new ACR("1")));
		assertTrue(voluntaryACRs.contains(new ACR("2")));
		
		assertEquals(2, voluntaryACRs.size());
		
		assertFalse(acrRequest.isEmpty());
	}
	
	
	public void testResolveClaimsLevelEssentialACRRequest()
		throws Exception {
		
		ClaimsRequest claims = new ClaimsRequest();
		
		List<String> essentialACRs = new ArrayList<>();
		essentialACRs.add("A");
		essentialACRs.add("B");
		claims.addIDTokenClaim("acr", ClaimRequirement.ESSENTIAL, null, essentialACRs);
		
		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid", "profile"),
			new ClientID("123"),
			new URI("https://example.com/in")).
			claims(claims).
			build();
		
		ACRRequest acrRequest = ACRRequest.resolve(authRequest);
		
		assertTrue(acrRequest.getEssentialACRs().contains(new ACR("A")));
		assertTrue(acrRequest.getEssentialACRs().contains(new ACR("B")));
		assertEquals(2, acrRequest.getEssentialACRs().size());
		
		assertNull(acrRequest.getVoluntaryACRs());
		
		assertFalse(acrRequest.isEmpty());
	}
	
	
	public void testResolveClaimsLevelVoluntaryACRRequest()
		throws Exception {
		
		ClaimsRequest claims = new ClaimsRequest();
		
		List<String> essentialACRs = new ArrayList<>();
		essentialACRs.add("A");
		essentialACRs.add("B");
		claims.addIDTokenClaim("acr", ClaimRequirement.VOLUNTARY, null, essentialACRs);

		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid", "profile"),
			new ClientID("123"),
			new URI("https://example.com/in")).
			claims(claims).
			build();
		
		ACRRequest acrRequest = ACRRequest.resolve(authRequest);
		
		assertNull(acrRequest.getEssentialACRs());
		
		assertTrue(acrRequest.getVoluntaryACRs().contains(new ACR("A")));
		assertTrue(acrRequest.getVoluntaryACRs().contains(new ACR("B")));
		assertEquals(2, acrRequest.getVoluntaryACRs().size());
		
		assertFalse(acrRequest.isEmpty());
	}
	
	
	public void testResolveMixedACRRequest()
		throws Exception {
		
		List<ACR> acrValues = new ArrayList<>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));
		
		ClaimsRequest claims = new ClaimsRequest();
		
		List<String> essentialACRs = new ArrayList<>();
		essentialACRs.add("A");
		essentialACRs.add("B");
		claims.addIDTokenClaim("acr", ClaimRequirement.ESSENTIAL, null, essentialACRs);

		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid", "profile"),
			new ClientID("123"),
			new URI("https://example.com/in")).
			acrValues(acrValues).
			claims(claims).
			build();
		
		ACRRequest acrRequest = ACRRequest.resolve(authRequest);
		
		assertTrue(acrRequest.getEssentialACRs().contains(new ACR("A")));
		assertTrue(acrRequest.getEssentialACRs().contains(new ACR("B")));
		assertEquals(2, acrRequest.getEssentialACRs().size());
		
		assertTrue(acrRequest.getVoluntaryACRs().contains(new ACR("1")));
		assertTrue(acrRequest.getVoluntaryACRs().contains(new ACR("2")));
		assertEquals(2, acrRequest.getVoluntaryACRs().size());
		
		assertFalse(acrRequest.isEmpty());
	}
	
	
	public void testApplyDefaultACR_nothingToApply()
		throws Exception {
		
		ACRRequest acrRequest = new ACRRequest(null, null);
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
		clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
		clientMetadata.applyDefaults();
		OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), clientMetadata, new Secret());
		
		acrRequest = acrRequest.applyDefaultACRs(clientInfo);
		
		assertTrue(acrRequest.isEmpty());
	}
	
	
	public void testApplyDefaultACR_explicitACRs_essential()
		throws Exception {
		
		ACRRequest acrRequest = new ACRRequest(Collections.singletonList(new ACR("1")), null);
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
		clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
		clientMetadata.applyDefaults();
		OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), clientMetadata, new Secret());
		
		acrRequest = acrRequest.applyDefaultACRs(clientInfo);
		
		assertEquals(new ACR("1"), acrRequest.getEssentialACRs().get(0));
		assertEquals(1, acrRequest.getEssentialACRs().size());
		
		assertNull(acrRequest.getVoluntaryACRs());
		
		assertFalse(acrRequest.isEmpty());
	}
	
	
	public void testApplyDefaultACR_explicitACRs_voluntary()
		throws Exception {
		
		ACRRequest acrRequest = new ACRRequest(null, Collections.singletonList(new ACR("1")));
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
		clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
		clientMetadata.applyDefaults();
		OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), clientMetadata, new Secret());
		
		acrRequest = acrRequest.applyDefaultACRs(clientInfo);
		
		assertNull(acrRequest.getEssentialACRs());
		
		assertEquals(new ACR("1"), acrRequest.getVoluntaryACRs().get(0));
		assertEquals(1, acrRequest.getVoluntaryACRs().size());
		
		assertFalse(acrRequest.isEmpty());
	}
	
	
	public void testApplyDefaultACR_applyRegisteredACRValue()
		throws Exception {
		
		ACRRequest acrRequest = new ACRRequest(null, null);
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
		clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
		clientMetadata.setDefaultACRs(Collections.singletonList(new ACR("1")));
		clientMetadata.applyDefaults();
		OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), clientMetadata, new Secret());
		
		acrRequest = acrRequest.applyDefaultACRs(clientInfo);
		
		assertNull(acrRequest.getEssentialACRs());
		
		assertEquals(new ACR("1"), acrRequest.getVoluntaryACRs().get(0));
		assertEquals(1, acrRequest.getVoluntaryACRs().size());
		
		assertFalse(acrRequest.isEmpty());
	}
	
	
	public void testApplyDefaultACR_applyRegisteredACRValuesMultiple()
		throws Exception {
		
		ACRRequest acrRequest = new ACRRequest(null, null);
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
		clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
		clientMetadata.setDefaultACRs(Arrays.asList(new ACR("1"), new ACR("2")));
		clientMetadata.applyDefaults();
		OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), clientMetadata, new Secret());
		
		acrRequest = acrRequest.applyDefaultACRs(clientInfo);
		
		assertNull(acrRequest.getEssentialACRs());
		
		assertEquals(new ACR("1"), acrRequest.getVoluntaryACRs().get(0));
		assertEquals(new ACR("2"), acrRequest.getVoluntaryACRs().get(1));
		assertEquals(2, acrRequest.getVoluntaryACRs().size());
		
		assertFalse(acrRequest.isEmpty());
	}
}