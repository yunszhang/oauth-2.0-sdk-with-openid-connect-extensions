package com.nimbusds.oauth2.sdk.tokenexchange;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.TypelessToken;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import junit.framework.TestCase;

public class TokenExchangeGrantTest extends TestCase {

  public void testConstructor() throws Exception {

    List<String> audiences = Collections.singletonList("audience");
    TokenTypeURI requestedTokenType = TokenTypeURI.parse("requestedTokenType");
    TypelessToken subjectToken = new TypelessToken("subjectToken");
    TokenTypeURI subjectTokenType = TokenTypeURI.parse("subjectTokenType");
    TypelessToken actorToken = new TypelessToken("actorToken");
    TokenTypeURI actorTokenType = TokenTypeURI.parse("actorTokenType");

    TokenExchangeGrant grant = new TokenExchangeGrant(audiences, requestedTokenType, subjectToken, subjectTokenType,
        actorToken, actorTokenType);

    assertEquals(GrantType.TOKEN_EXCHANGE, grant.getType());
    assertEquals(audiences, grant.getAudiences());
    assertEquals(requestedTokenType, grant.getRequestedTokenType());
    assertEquals(subjectToken, grant.getSubjectToken());
    assertEquals(subjectTokenType, grant.getSubjectTokenType());
    assertEquals(actorToken, grant.getActorToken());
    assertEquals(actorTokenType, grant.getActorTokenType());

    Map<String, List<String>> params = grant.toParameters();
    assertEquals(Collections.singletonList("urn:ietf:params:oauth:grant-type:token-exchange"),
        params.get("grant_type"));
    assertEquals(Collections.singletonList("audience"), params.get("audience"));
    assertEquals(Collections.singletonList("requestedTokenType"), params.get("requested_token_type"));
    assertEquals(Collections.singletonList("subjectToken"), params.get("subject_token"));
    assertEquals(Collections.singletonList("subjectTokenType"), params.get("subject_token_type"));
    assertEquals(Collections.singletonList("actorToken"), params.get("actor_token"));
    assertEquals(Collections.singletonList("actorTokenType"), params.get("actor_token_type"));
    assertEquals(7, params.size());

    grant = TokenExchangeGrant.parse(params);
    assertEquals(GrantType.TOKEN_EXCHANGE, grant.getType());
    assertEquals(Collections.singletonList("audience"), grant.getAudiences());
    assertEquals(requestedTokenType, grant.getRequestedTokenType());
    assertEquals(subjectToken, grant.getSubjectToken());
    assertEquals(subjectTokenType, grant.getSubjectTokenType());
    assertEquals(actorToken, grant.getActorToken());
    assertEquals(actorTokenType, grant.getActorTokenType());
  }

  public void testConstructorOfMissingMandatorySubjectToken() throws URISyntaxException {
    List<String> audiences = Collections.singletonList("audience");
    TokenTypeURI requestedTokenType = TokenTypeURI.parse("requestedTokenType");
    TypelessToken actorToken = new TypelessToken("actorToken");
    TokenTypeURI actorTokenType = TokenTypeURI.parse("actorTokenType");

    try {
      new TokenExchangeGrant(audiences, requestedTokenType, null, null, actorToken, actorTokenType);
      fail();
    } catch (Exception e) {
      assertTrue(e instanceof IllegalArgumentException);
      assertEquals("The subject token must not be null", e.getMessage());
    }
  }

  public void testToParametersMissingOptionalActorTokenAndActorTokenType() throws URISyntaxException, ParseException {
    List<String> audiences = Collections.singletonList("audience");
    TokenTypeURI requestedTokenType = TokenTypeURI.parse("requestedTokenType");
    TypelessToken subjectToken = new TypelessToken("subjectToken");
    TokenTypeURI subjectTokenType = TokenTypeURI.parse("subjectTokenType");

    TokenExchangeGrant grant = new TokenExchangeGrant(audiences, requestedTokenType, subjectToken, subjectTokenType,
        null, null);

    Map<String, List<String>> params = grant.toParameters();
    assertEquals(Collections.singletonList("urn:ietf:params:oauth:grant-type:token-exchange"),
        params.get("grant_type"));
    assertEquals(Collections.singletonList("audience"), grant.getAudiences());
    assertEquals(Collections.singletonList("requestedTokenType"), params.get("requested_token_type"));
    assertEquals(Collections.singletonList("subjectToken"), params.get("subject_token"));
    assertEquals(Collections.singletonList("subjectTokenType"), params.get("subject_token_type"));
    assertEquals(5, params.size());
  }


  public void testParse() throws Exception {

    Map<String, List<String>> params = new HashMap<>();
    params.put("grant_type", Collections.singletonList(GrantType.TOKEN_EXCHANGE.getValue()));
    params.put("audience", Collections.singletonList("audience"));
    params.put("requested_token_type", Collections.singletonList("requestedTokenType"));
    params.put("subject_token", Collections.singletonList("subjectToken"));
    params.put("subject_token_type", Collections.singletonList("subjectTokenType"));
    params.put("actor_token", Collections.singletonList("actorToken"));
    params.put("actor_token_type", Collections.singletonList("actorTokenType"));

    TokenExchangeGrant grant = TokenExchangeGrant.parse(params);

    assertEquals(GrantType.TOKEN_EXCHANGE, grant.getType());
    assertEquals(Collections.singletonList("audience"), grant.getAudiences());
    assertEquals("requestedTokenType", grant.getRequestedTokenType().getUri().toString());
    assertEquals("subjectToken", grant.getSubjectToken().getValue());
    assertEquals("subjectTokenType", grant.getSubjectTokenType().getUri().toString());
    assertEquals("actorToken", grant.getActorToken().getValue());
    assertEquals("actorTokenType", grant.getActorTokenType().getUri().toString());
  }

  public void testParseMissingGrantType() {

    Map<String, List<String>> params = new HashMap<>();
    params.put("grant_type", null);
    params.put("audience", Collections.singletonList("audience"));
    params.put("requested_token_type", Collections.singletonList("requestedTokenType"));
    params.put("subject_token", Collections.singletonList("subjectToken"));
    params.put("subject_token_type", Collections.singletonList("subjectTokenType"));
    params.put("actor_token", Collections.singletonList("actorToken"));
    params.put("actor_token_type", Collections.singletonList("actorTokenType"));

    try {
      TokenExchangeGrant.parse(params);
      fail();
    } catch (ParseException e) {
      assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
      assertEquals("Invalid request: Missing grant_type parameter",
          e.getErrorObject().getDescription());
      assertNull(e.getErrorObject().getURI());
    }
  }

  public void testParseUnsupportedGrant() {

    Map<String, List<String>> params = new HashMap<>();
    params.put("grant_type", Collections.singletonList("no-such-grant"));
    params.put("audience", Collections.singletonList("audience"));
    params.put("requested_token_type", Collections.singletonList("requestedTokenType"));
    params.put("subject_token", Collections.singletonList("subjectToken"));
    params.put("subject_token_type", Collections.singletonList("subjectTokenType"));
    params.put("actor_token", Collections.singletonList("actorToken"));
    params.put("actor_token_type", Collections.singletonList("actorTokenType"));

    try {
      TokenExchangeGrant.parse(params);
      fail();
    } catch (ParseException e) {
      assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode(), e.getErrorObject().getCode());
      assertEquals("Unsupported grant type: The grant_type must be urn:ietf:params:oauth:grant-type:token-exchange",
          e.getErrorObject().getDescription());
      assertNull(e.getErrorObject().getURI());
    }
  }

  public void testParseMissingSubjectTokenAndSubjectTokenType() {
    Map<String, List<String>> params = new HashMap<>();
    params.put("grant_type", Collections.singletonList(GrantType.TOKEN_EXCHANGE.getValue()));
    params.put("audience", Collections.singletonList("audience"));
    params.put("requested_token_type", Collections.singletonList("requestedTokenType"));
    params.put("actor_token", Collections.singletonList("actorToken"));
    params.put("actor_token_type", Collections.singletonList("actorTokenType"));

    try {
      TokenExchangeGrant.parse(params);
      fail();
    } catch (ParseException e) {
      assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
      assertEquals("Invalid request: Missing or empty subject_token parameter",
          e.getErrorObject().getDescription());
      assertNull(e.getErrorObject().getURI());
    }
  }

  public void testParseMissingOptionalActorTokenAndActorTokenType() throws Exception {
    Map<String, List<String>> params = new HashMap<>();
    params.put("grant_type", Collections.singletonList(GrantType.TOKEN_EXCHANGE.getValue()));
    params.put("audience", Collections.singletonList("audience"));
    params.put("requested_token_type", Collections.singletonList("requestedTokenType"));
    params.put("subject_token", Collections.singletonList("subjectToken"));
    params.put("subject_token_type", Collections.singletonList("subjectTokenType"));

    TokenExchangeGrant grant = TokenExchangeGrant.parse(params);
    assertEquals(GrantType.TOKEN_EXCHANGE, grant.getType());
    assertEquals(Collections.singletonList("audience"), grant.getAudiences());
    assertEquals("requestedTokenType", grant.getRequestedTokenType().getUri().toString());
    assertEquals("subjectToken", grant.getSubjectToken().getValue());
    assertEquals("subjectTokenType", grant.getSubjectTokenType().getUri().toString());
    assertNull("actorToken", grant.getActorToken());
    assertNull("actorTokenType", grant.getActorTokenType());
  }

  public void testEquality() throws ParseException, URISyntaxException {
    List<String> audiences = Collections.singletonList("audience");
    TokenTypeURI requestedTokenType = TokenTypeURI.parse("requestedTokenType");
    TypelessToken subjectToken = new TypelessToken("subjectToken");
    TokenTypeURI subjectTokenType = TokenTypeURI.parse("subjectTokenType");
    TypelessToken actorToken = new TypelessToken("actorToken");
    TokenTypeURI actorTokenType = TokenTypeURI.parse("actorTokenType");

    TokenExchangeGrant grant1 = new TokenExchangeGrant(audiences, requestedTokenType, subjectToken, subjectTokenType,
        actorToken, actorTokenType);

    TokenExchangeGrant grant2 = new TokenExchangeGrant(audiences, requestedTokenType, subjectToken, subjectTokenType,
        actorToken, actorTokenType);

    assertEquals(grant1, grant2);
  }

  public void testInequality() throws ParseException, URISyntaxException {
    List<String> audiences = Collections.singletonList("audience");
    TokenTypeURI requestedTokenType = TokenTypeURI.parse("requestedTokenType");
    TypelessToken subjectToken = new TypelessToken("subjectToken");
    TokenTypeURI subjectTokenType = TokenTypeURI.parse("subjectTokenType");
    TypelessToken actorToken = new TypelessToken("actorToken");
    TokenTypeURI actorTokenType = TokenTypeURI.parse("actorTokenType");
    TokenTypeURI anotherActorTokenType = TokenTypeURI.parse("anotherActorTokenType");

    TokenExchangeGrant grant1 = new TokenExchangeGrant(audiences, requestedTokenType, subjectToken, subjectTokenType,
        actorToken, actorTokenType);

    TokenExchangeGrant grant2 = new TokenExchangeGrant(audiences, requestedTokenType, subjectToken, subjectTokenType,
        actorToken, anotherActorTokenType);

    assertFalse(grant1.equals(grant2));
  }
}