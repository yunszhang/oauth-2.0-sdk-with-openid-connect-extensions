package com.nimbusds.oauth2.sdk.ciba;

import junit.framework.TestCase;

public class BackChannelTokenDeliveryModeTest extends TestCase {
	public void testParse() {
		BackChannelTokenDeliveryMode mode = BackChannelTokenDeliveryMode.parse("poll");
		assertEquals(BackChannelTokenDeliveryMode.POLL, mode);

		mode = BackChannelTokenDeliveryMode.parse("ping");
		assertEquals(BackChannelTokenDeliveryMode.PING, mode);

		mode = BackChannelTokenDeliveryMode.parse("push");
		assertEquals(BackChannelTokenDeliveryMode.PUSH, mode);

		try {
			mode = BackChannelTokenDeliveryMode.parse("asd");
			if(mode != null) {
				assertTrue("BackChannelTokenDeliveryMode.parse should not return valid mode with invalid input", false);
			} else {
				assertTrue("BackChannelTokenDeliveryMode.parse throw invalid argument with invalid input", false);
			}
		} catch (IllegalArgumentException e) {
			assertEquals(e.getMessage(), "Invalid BackChannel Token Delivery Mode");

		}
	}

}
