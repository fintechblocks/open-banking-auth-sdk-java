package com.fintechblocks.java.sdk;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public final class Utils {
  private Utils(){
    throw new IllegalStateException( "Do not instantiate this class." );
  }


  public static void setFormUrlParameters(HttpURLConnection connection, Map<String, String> params) {
    try {
      StringBuilder urlParamsStr = new StringBuilder();
      boolean first = true;
      for (Map.Entry<String, String> entry : params.entrySet()) {
        if (first) {
          first = false;
        } else {
          urlParamsStr.append("&");
        }
        urlParamsStr.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
        urlParamsStr.append("=");
        urlParamsStr.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
      }
      byte[] postData = urlParamsStr.toString().getBytes(StandardCharsets.UTF_8);
      try (DataOutputStream wr = new DataOutputStream(connection.getOutputStream())) {
        wr.write(postData);
      }
    } catch (Exception e) {
      throw new SdkRuntimeException("Unexpected error while try to set url parameters.", e);
    }
  }

  @SuppressWarnings("deprecation")
  public static String createJWT(String privateKeyStr, Map<String, Object> claims) throws Exception {
    PrivateKey privateKey = generatePrivateKeyFromString(privateKeyStr);
    return Jwts.builder().addClaims(claims).signWith(privateKey, SignatureAlgorithm.RS256).compact();
  }

  @SuppressWarnings("deprecation")
  public static String sign(String privateKeyStr, String payload, Map<String, Object> headers) throws Exception {
    PrivateKey privateKey = generatePrivateKeyFromString(privateKeyStr);
    return Jwts.builder().setHeader(headers).setPayload(payload).signWith(privateKey, SignatureAlgorithm.RS256)
        .compact();
  }

  public static Claims decodeJwt(String jwt) {
    try {
      return Jwts.parser().base64UrlDecodeWith(io.jsonwebtoken.io.Decoders.BASE64).parseClaimsJws(jwt).getBody();
    } catch (Exception e) {
      throw new SdkRuntimeException("Unexpected error while try to decode jwt.", e);
    }
  }

  private static PrivateKey generatePrivateKeyFromString(String keyStr) throws Exception {
    PrivateKey privateKey = null;
    if (keyStr.length() > 1) {
      keyStr = keyStr.replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "")
          .replaceAll("\\s+", "").replaceAll("\\r+", "").replaceAll("\\n+", "");
      byte[] data = Base64.getDecoder().decode(keyStr);
      ASN1EncodableVector v = new ASN1EncodableVector();
      v.add(new ASN1Integer(0));
      ASN1EncodableVector v2 = new ASN1EncodableVector();
      v2.add(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.rsaEncryption.getId()));
      v2.add(DERNull.INSTANCE);
      v.add(new DERSequence(v2));
      v.add(new DEROctetString(data));
      ASN1Sequence seq = new DERSequence(v);
      byte[] privKey = seq.getEncoded("DER");

      PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privKey);
      KeyFactory fact = KeyFactory.getInstance("RSA");
      privateKey = fact.generatePrivate(spec);
    }
    return privateKey;
  }

  public static JsonNode stringToJson(String json) {
    try {
      return new ObjectMapper().readTree(json);
    } catch (IOException e) {
      throw new SdkRuntimeException("Unexpected error while try to parse string to json.", e);
    }
  }

  public static String responseToString(HttpURLConnection connection) {
    try {
      BufferedReader reader;
      if (100 <= connection.getResponseCode() && connection.getResponseCode() <= 399) {
    	  reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
      } else {
    	  reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
      }
      String inputLine;
      StringBuilder content = new StringBuilder();
      while ((inputLine = reader.readLine()) != null) {
        content.append(inputLine);
      }
      reader.close();
      return content.toString();
    } catch (Exception e) {
      throw new SdkRuntimeException("Unexpected error while get response content.", e);
    }
  }

  public static String fileToString(File file) {
    try {
      String str = "";
      StringBuilder result = new StringBuilder();
      BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
      while ((str = bufferedReader.readLine()) != null) {
        result.append(str + "\n");
      }
      bufferedReader.close();
      return result.toString();
    } catch (Exception e) {
      throw new SdkRuntimeException("Unexpected error while convert file to string.", e);
    }
  }
  
  public static long createExpirationDate(int min) {
    Date now = new Date();
    return Math.round((now.getTime() + (min * 60000)) / 1000);
  }
}
