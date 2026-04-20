package org.fnm.rfc9421TestClient;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.authlete.hms.SigningInfo;
import com.authlete.hms.fapi.FapiResourceRequestSigner;
import com.nimbusds.jose.jwk.JWK;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SignatureException;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;


/**
 * uses plain java.net.HttpClient
 */
@SpringBootApplication
public class Rfc9421TestClientPlain {

    private static final String apiUrl = "http://localhost:8080/api/verify";;

    private static final String SIGNING_KEY =
            "{\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"alg\": \"ES256\",\n" +
                    "  \"crv\": \"P-256\",\n" +
                    "  \"x\": \"R-z3wlMAAQ73arr3JkxfP04woVLm1zHJXX2IGCm7z5c\",\n" +
                    "  \"y\": \"zs5TKDbreY-5rUqx1xiMc1aKP9CWq3dL6wZJ3wVTf50\",\n" +
                    "  \"d\": \"E67QqVgry3Y7vlMyuEID4CRbubQON9Bf-PLaB3lIdFs\",\n" +
                    "  \"kid\": \"snIZq-_NvzkKV-IdiM348BCz_RKdwmufnrPubsKKyio\",\n" +
                    "  \"use\": \"sig\"\n" +
                    "}";

    public static void main(String[] args) throws IOException, SignatureException, ParseException, InterruptedException {

        SpringApplication.run(Rfc9421TestClientPlain.class, args);

        // Build request body manually as x-www-form-urlencoded
        List<String[]> bodyElements = new ArrayList<>();
        bodyElements.add(new String[]{"grant_type", "client_credentials"});
        bodyElements.add(new String[]{"requested-token-type", "urn:ietf:params:oauth:token-type:jwt"});
        bodyElements.add(new String[]{"principal_id", "9801000050702"});
        bodyElements.add(new String[]{"person_id", "761337610411353650%5E%5E%5E%262.16.756.5.30.1.109.6.5.3.1.1%26ISO"});
        bodyElements.add(new String[]{"principal_id", "9801000050702"});
        bodyElements.add(new String[]{"scope", "user%2F*.*+openid+fhirUser+purpose_of_use%3Durn%3Aoid%3A2.16.756.5.30.1.127.3.10.5%7CAUTO+subject_role%3Durn%3Aoid%3A2.16.756.5.30.1.127.3.10.6%7CTC"});

        String formBody = formEncode(bodyElements);
        byte[] bodyBytes = formBody.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // Compute content digest
        byte[] contentDigestAsBytes = DigestUtils.sha512(formBody);
        String sha512Base64 = Base64.getEncoder().encodeToString(contentDigestAsBytes);

        String authZ = "Basic <redacted>";

        String contentDigest = "sha-512=:" + sha512Base64 + "=:";

        // Sign the request
        JWK signingKey = JWK.parse(SIGNING_KEY);
        Instant timestamp = Instant.now();

        FapiResourceRequestSigner signer = new FapiResourceRequestSigner()
                .setMethod("POST")
                .setTargetUri(URI.create(apiUrl))
                .setAuthorization(authZ)
                .setContentDigest(contentDigest)
                .setSigningKey(signingKey)
                .setCreated(timestamp);

        SigningInfo signingInfo = signer.sign();

        String signatureMetadata = signingInfo.getSerializedSignatureMetadata();
        String metadataHeaderValue = "sig1=" + signatureMetadata;

        String signature = signingInfo.getSerializedSignature();
        String signatureHeaderValue = "sig1=" + signature;

        // Build java.net.HttpClient request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(apiUrl))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", authZ)
                .header("Content-Digest", contentDigest)
                .header("Signature-Input", metadataHeaderValue)
                .header("Signature", signatureHeaderValue)
                .POST(HttpRequest.BodyPublishers.ofByteArray(bodyBytes))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        String result = response.body();

        // TODO extract extension and scope
        Algorithm algorithm = Algorithm.HMAC512("your-secret-key");

        JWTVerifier verifier = JWT.require(algorithm)
                .acceptLeeway(1)
                .acceptExpiresAt(5)
                .build();

        DecodedJWT jwt = verifier.verify(result);

        Base64.Decoder decoder = Base64.getUrlDecoder();
        String payload = new String(decoder.decode(jwt.getPayload()), java.nio.charset.StandardCharsets.UTF_8);

        System.out.println("Token payload is: ");
        System.out.println(payload);

        System.out.println("Received data:");
        System.out.println("Issuer: " + jwt.getIssuer());
        System.out.println("Subject: " + jwt.getSubject());
        System.out.println("Audience: " + jwt.getAudience());
        System.out.println("Issued: " + jwt.getIssuedAt());
        System.out.println("Expires: " + jwt.getExpiresAt());
        System.out.println("UserId: " + jwt.getClaim("userId"));
        System.out.println("Scope: " + jwt.getClaim("scope"));
        System.out.println("Extensions: " + jwt.getClaim("extensions"));
    }

    private static String formEncode(List<String[]> pairs) {
        return pairs.stream()
                .map(pair -> urlEncode(pair[0]) + "=" + urlEncode(pair[1]))
                .reduce((a, b) -> a + "&" + b)
                .orElse("");
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }
}
