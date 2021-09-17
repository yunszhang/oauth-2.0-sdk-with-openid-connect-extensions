package com.nimbusds.oauth2.sdk;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import java.util.HashMap;
import java.util.Map;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;

public class TokenExchangeResponseTest extends TestCase {

  public void testConstructor() throws ParseException {
    Tokens tokens = new Tokens(new BearerAccessToken(), new RefreshToken());
    TokenTypeURI issuedTokenType = TokenTypeURI.ACCESS_TOKEN;
    Scope scope = Scope.parse("openid");
    TokenExchangeResponse response = new TokenExchangeResponse(tokens, issuedTokenType, scope);

    assertTrue(response.indicatesSuccess());
    assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
    assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
    assertEquals(tokens.getRefreshToken(), response.getTokens().getRefreshToken());
    assertTrue(response.getCustomParameters().isEmpty());
    assertEquals(TokenTypeURI.ACCESS_TOKEN, response.getIssuedTokenType());
    assertEquals(scope, response.getScope());

    HTTPResponse httpResponse = response.toHTTPResponse();
    response = TokenExchangeResponse.parse(httpResponse);

    assertTrue(response.indicatesSuccess());
    assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
    assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
    assertEquals(tokens.getRefreshToken(), response.getTokens().getRefreshToken());
    assertTrue(response.getCustomParameters().isEmpty());
    assertEquals(TokenTypeURI.ACCESS_TOKEN, response.getIssuedTokenType());
    assertEquals(scope, response.getScope());
  }

  public void testConstructorWithCustomParams() throws ParseException {
    Tokens tokens = new Tokens(new BearerAccessToken(), new RefreshToken());
    Map<String, Object> customParams = new HashMap<>();
    customParams.put("sub_sid", "abc");
    TokenTypeURI issuedTokenType = TokenTypeURI.ACCESS_TOKEN;
    Scope scope = Scope.parse("openid");
    TokenExchangeResponse response = new TokenExchangeResponse(tokens, customParams, issuedTokenType, scope);

    assertTrue(response.indicatesSuccess());
    assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
    assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
    assertEquals(tokens.getRefreshToken(), response.getTokens().getRefreshToken());
    assertEquals("abc", (String) response.getCustomParameters().get("sub_sid"));
    assertEquals(TokenTypeURI.ACCESS_TOKEN, response.getIssuedTokenType());
    assertEquals(scope, response.getScope());

    HTTPResponse httpResponse = response.toHTTPResponse();
    response = TokenExchangeResponse.parse(httpResponse);

    assertTrue(response.indicatesSuccess());
    assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
    assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
    assertEquals(tokens.getRefreshToken(), response.getTokens().getRefreshToken());
    assertEquals("abc", (String) response.getCustomParameters().get("sub_sid"));
    assertEquals(TokenTypeURI.ACCESS_TOKEN, response.getIssuedTokenType());
    assertEquals(scope, response.getScope());
  }

  public void testParseJSONObject() throws ParseException {
    JSONObject jsonObject = new JSONObject();
    jsonObject.put("access_token", "oz5SJE9NP5Bw17tA8kqYVjFnhPzZ56-LGB1cJHb9xZM");
    jsonObject.put("token_type", "Bearer");
    jsonObject.put("expires_in", 3600);
    jsonObject.put("refresh_token", "hl9e7lh1sKLxnwCYN_jYjYqqlTbaqLF9xBJxEYtHGyE");
    jsonObject.put("issued_token_type", "urn:ietf:params:oauth:token-type:access_token");
    jsonObject.put("scope", "openid");
    jsonObject.put("custom_parameter", "parameter_value");

    TokenExchangeResponse response = TokenExchangeResponse.parse(jsonObject);
    assertEquals("oz5SJE9NP5Bw17tA8kqYVjFnhPzZ56-LGB1cJHb9xZM", response.getTokens().getBearerAccessToken().getValue());
    assertEquals(3600L, response.getTokens().getBearerAccessToken().getLifetime());
    assertEquals("hl9e7lh1sKLxnwCYN_jYjYqqlTbaqLF9xBJxEYtHGyE", response.getTokens().getRefreshToken().getValue());
    assertEquals("urn:ietf:params:oauth:token-type:access_token", response.getIssuedTokenType().getURI().toString());
    assertEquals("openid", response.getScope().toString());
    assertEquals("parameter_value", response.getCustomParameters().get("custom_parameter"));
    assertEquals(1, response.getCustomParameters().size());
  }

  public void testParseExampleFromRFC8693() throws ParseException {
    String jsonString = "\n"
        + "    {\n"
        + "     \"access_token\":\"eyJhbGciOiJFUzI1NiIsImtpZCI6IjllciJ9.eyJhdWQiOiJodHRwczovL2JhY2tlbmQuZXhhbXBsZS5jb20i"
        + "LCJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiwiZXhwIjoxNDQxOTE3NTkzLCJpYXQiOjE0NDE5MTc1MzMsInN1YiI6ImJkY0BleGFt"
        + "cGxlLmNvbSIsInNjb3BlIjoiYXBpIn0.40y3ZgQedw6rxf59WlwHDD9jryFOr0_Wh3CGozQBihNBhnXEQgU85AI9x3KmsPottVMLPIWvmDCMy"
        + "5-kdXjwhw\",\n"
        + "     \"issued_token_type\":\n"
        + "         \"urn:ietf:params:oauth:token-type:access_token\",\n"
        + "     \"token_type\":\"Bearer\",\n"
        + "     \"expires_in\":60\n"
        + "    }";

    JSONObject jsonObject = JSONObjectUtils.parse(jsonString);
    TokenExchangeResponse response = TokenExchangeResponse.parse(jsonObject);
    String expectedAccessToken = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjllciJ9.eyJhdWQiOiJodHRwczovL2JhY2tlbmQuZXhhbXBsZS5jb20i"
        + "LCJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiwiZXhwIjoxNDQxOTE3NTkzLCJpYXQiOjE0NDE5MTc1MzMsInN1YiI6ImJkY0BleGFt"
        + "cGxlLmNvbSIsInNjb3BlIjoiYXBpIn0.40y3ZgQedw6rxf59WlwHDD9jryFOr0_Wh3CGozQBihNBhnXEQgU85AI9x3KmsPottVMLPIWvmDCMy"
        + "5-kdXjwhw";
    assertEquals(expectedAccessToken, response.getTokens().getBearerAccessToken().getValue());
    assertEquals(60L, response.getTokens().getBearerAccessToken().getLifetime());
    assertNull(response.getTokens().getRefreshToken());
    assertEquals("urn:ietf:params:oauth:token-type:access_token", response.getIssuedTokenType().getURI().toString());
    assertNull(response.getScope());
    assertEquals(0, response.getCustomParameters().size());
  }
}