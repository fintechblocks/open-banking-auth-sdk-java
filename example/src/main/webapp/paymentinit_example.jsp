<%@page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@page import="java.io.File"%>
<%@page import="java.io.IOException"%>
<%@page import="java.io.OutputStream"%>
<%@page import="java.io.PrintWriter"%>
<%@page import="java.net.HttpURLConnection"%>
<%@page import="java.net.URL"%>
<%@page import="java.util.HashMap"%>
<%@page import="java.util.Map"%>

<%@page import="javax.servlet.ServletException"%>
<%@page import="javax.servlet.http.HttpServlet"%>
<%@page import="javax.servlet.http.HttpServletRequest"%>
<%@page import="javax.servlet.http.HttpServletResponse"%>

<%@page import="org.apache.commons.lang.RandomStringUtils"%>

<%@page import="com.fasterxml.jackson.databind.JsonNode"%>
<%@page import="com.fintechblocks.java.sdk.OpenBankingAuth"%>
<%@page import="com.fintechblocks.java.sdk.Utils"%>
<%
  String clientId = "myapp@payment-init-1.0";
  String apiUrl = "https://<sandbox_api_host_of_the_bank>/payment-init-1.0/open-banking/v3.1/pisp";
  String scope = "payments";
  String redirectUri = "http://localhost:8080/example/paymentinit_example.jsp";
  String tokenEndpointUri = "https://<sandbox_api_host_of_the_bank>/auth/realms/ftb-sandbox/protocol/openid-connect/token";
  String authorizationEndpointURI = "https://<sandbox_api_host_of_the_bank>/auth/realms/ftb-sandbox/protocol/openid-connect/auth";

  String webRootPath = application.getRealPath("/").replace('\\', '/');
  Boolean code = false;
  String intentId = "";

  File privateKeyFile = new File(webRootPath + "WEB-INF/classes/private_key.pem");
  File paymentFile = new File(webRootPath + "WEB-INF/classes/domestic-payment-consent.json");
  String payment = Utils.fileToString(paymentFile);

  String privateKey = Utils.fileToString(privateKeyFile);
  String keyID = "AfFNfYXZf3arkkxv_9zqRU4d1jp1b39Edw1bxfEK5-4";

  OpenBankingAuth paymentInitAuth = new OpenBankingAuth(clientId, privateKey, keyID, redirectUri, tokenEndpointUri,
      authorizationEndpointURI, scope);

  if (request.getParameter("code") == null) {
    try {
      String accessToken = paymentInitAuth.getAccessToken();

      Map<String, String> headers = new HashMap<String, String>();
      headers.put("x-jws-signature",
          paymentInitAuth.createSignatureHeader(payment, "C=UK, ST=England, L=London, O=Acme Ltd."));
      headers.put("x-idempotency-key", RandomStringUtils.random(20, true, true));

      JsonNode paymentJson = callAPI(accessToken, apiUrl, "domestic-payment-consents", "POST", headers, payment);

      intentId = paymentJson.get("Data").get("ConsentId").asText();

      String state = RandomStringUtils.random(20, true, true);
      String nonce = RandomStringUtils.random(20, true, true);
      String authUrl = paymentInitAuth.generateAuthorizationUrl(intentId, state, nonce);

      response.sendRedirect(authUrl + "&state=" + intentId);
    } catch (Exception e) {
      out.println(e.toString());
      e.printStackTrace();
    }
  } else {
    try {
      JsonNode newAccessTokenJson = paymentInitAuth.exchangeToken(request.getParameter("code"));
      String newAccessToken = newAccessTokenJson.get("access_token").asText();
      intentId = request.getParameter("state");
      JsonNode result = callAPI(newAccessToken, apiUrl, "domestic-payment-consents/" + intentId, "GET", null, null);
      out.println(result.toString());
    } catch (Exception e) {
      out.println(e.toString());
      e.printStackTrace();
    }
  }
%>
<%!private JsonNode callAPI(String accessToken, String apiUrl, String endpoint, String method,
      Map<String, String> headers, String body) throws IOException {
    URL url = new URL(apiUrl + "/" + endpoint);
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    connection.setRequestMethod(method);
    connection.setRequestProperty("Authorization", "Bearer " + accessToken);
    connection.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
    connection.setRequestProperty("Accept", "application/json");
    connection.setDoOutput(true);
    connection.setDoInput(true);

    if (headers != null) {
      for (Map.Entry<String, String> header : headers.entrySet()) {
        connection.setRequestProperty(header.getKey(), header.getValue());
      }
    }

    if (body != null) {
      OutputStream outputStream = connection.getOutputStream();
      outputStream.write(body.getBytes("UTF-8"));
      outputStream.close();
    }

    return Utils.stringToJson(Utils.responseToString(connection));
  }%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Payment test</title>
</head>
<body>
</body>
</html>