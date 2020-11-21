package com.nimbusds.oauth2.sdk.dpop;


import java.net.URI;
import java.text.ParseException;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.JWTID;


public class DPoPUtilsTest extends TestCase {
	
	
	static final JWTID JTI = new JWTID(96 / 8);
	
	
	static final String HTM = "POST";
	
	
	static final URI HTU = URI.create("https://c2id.com/token");
	
	
	static final Date IAT = DateUtils.fromSecondsSinceEpoch(3600);


	public void testCreateClaimsSet() throws ParseException {
		
		JWTClaimsSet jwtClaimsSet = DPoPUtils.createJWTClaimsSet(
			JTI,
			HTM,
			HTU,
			IAT
		);
		
		assertEquals(JTI.getValue(), jwtClaimsSet.getJWTID());
		assertEquals(HTM, jwtClaimsSet.getStringClaim("htm"));
		assertEquals(HTU, jwtClaimsSet.getURIClaim("htu"));
		assertEquals(IAT, jwtClaimsSet.getIssueTime());
		
		assertEquals(4, jwtClaimsSet.getClaims().size());
	}


	public void testCreateClaimsSet_jtiNull() {
		
		try {
			DPoPUtils.createJWTClaimsSet(
				null,
				HTM,
				HTU,
				IAT
			);
			fail();
		} catch (NullPointerException e) {
			// ok
		}
	}


	public void testCreateClaimsSet_htmNull() {
		
		try {
			DPoPUtils.createJWTClaimsSet(
				JTI,
				null,
				HTU,
				IAT
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The HTTP method (htu) is required", e.getMessage());
		}
	}


	public void testCreateClaimsSet_htuNull() {
		
		try {
			DPoPUtils.createJWTClaimsSet(
				JTI,
				HTM,
				null,
				IAT
			);
			fail();
		} catch (NullPointerException e) {
			// ok
		}
	}
	
	
	public void testCreateClaimsSet_htuQueryString() {
		
		try {
			DPoPUtils.createJWTClaimsSet(
				JTI,
				HTM,
				URI.create(HTU + "?query"),
				IAT
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The HTTP URI (htu) must not have a query", e.getMessage());
		}
	}
	
	
	public void testCreateClaimsSet_htuFragmentString() {
		
		try {
			DPoPUtils.createJWTClaimsSet(
				JTI,
				HTM,
				URI.create(HTU + "#fragment"),
				IAT
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The HTTP URI (htu) must not have a fragment", e.getMessage());
		}
	}
	
	
	public void testCreateClaimsSet_iatNull() {
		
		try {
			DPoPUtils.createJWTClaimsSet(
				JTI,
				HTM,
				HTU,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The issue time (iat) is required", e.getMessage());
		}
	}
}
