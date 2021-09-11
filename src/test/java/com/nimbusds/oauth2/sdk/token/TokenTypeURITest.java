package com.nimbusds.oauth2.sdk.token;

import com.nimbusds.oauth2.sdk.ParseException;
import java.net.URISyntaxException;
import junit.framework.TestCase;

public class TokenTypeURITest extends TestCase {

  public void testParseKnownUri() throws URISyntaxException {
    TokenTypeURI tokenTypeURI1 = TokenTypeURI.parse("urn:ietf:params:oauth:token-type:access_token");
    TokenTypeURI tokenTypeURI2 = TokenTypeURI.parse("urn:ietf:params:oauth:token-type:access_token");

    assertSame(tokenTypeURI1, tokenTypeURI2);
  }

  public void testParseUnknownUri() throws URISyntaxException {
    TokenTypeURI tokenTypeURI1 = TokenTypeURI.parse("urn:ietf:params:oauth:token-type:unknown_token");
    TokenTypeURI tokenTypeURI2 = TokenTypeURI.parse("urn:ietf:params:oauth:token-type:unknown_token");

    assertEquals(tokenTypeURI1, tokenTypeURI2);
    assertEquals(tokenTypeURI1.hashCode(), tokenTypeURI2.hashCode());
  }

  public void testParseNullUri() {
    try {
      TokenTypeURI.parse(null);
      fail();
    } catch (Exception e) {
      assertTrue(e instanceof IllegalArgumentException);
      assertEquals("The uri value must not be null", e.getMessage());
    }
  }
}