package com.nimbusds.oauth2.sdk.ciba;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;


public class BackChannelTokenDeliveryModeTest extends TestCase {
	
	
	public void testParse() throws ParseException {
		
		BackChannelTokenDeliveryMode mode = BackChannelTokenDeliveryMode.parse("poll");
		assertEquals(BackChannelTokenDeliveryMode.POLL, mode);
		
		mode = BackChannelTokenDeliveryMode.parse("ping");
		assertEquals(BackChannelTokenDeliveryMode.PING, mode);
		
		mode = BackChannelTokenDeliveryMode.parse("push");
		assertEquals(BackChannelTokenDeliveryMode.PUSH, mode);
	}
	
	
	public void testParseIllegal() {

		try {
			BackChannelTokenDeliveryMode.parse("asd");
			fail();
		} catch (ParseException e) {
			assertEquals(e.getMessage(), "Invalid CIBA token delivery mode: asd");
		}
	}
}
