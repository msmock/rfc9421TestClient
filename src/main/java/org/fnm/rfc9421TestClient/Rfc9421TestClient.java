package org.fnm.rfc9421TestClient;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.authlete.hms.SigningInfo;
import com.authlete.hms.fapi.FapiResourceRequestSigner;
import com.nimbusds.jose.jwk.JWK;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.SignatureException;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@SpringBootApplication
public class Rfc9421TestClient {

    // private static final String apiUrl = "http://localhost:8080/api/verify";

    private static final String apiUrl = "https://node-express-tracer.onrender.com/";

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

    public static void main(String[] args) throws IOException, SignatureException, ParseException {

        SpringApplication.run(Rfc9421TestClient.class, args);

        // build and attach body elements
        final List<NameValuePair> bodyElements = new ArrayList<NameValuePair>();
        bodyElements.add(new BasicNameValuePair("grant_type", "client_credentials"));
        bodyElements.add(new BasicNameValuePair("requested-token-type", "urn:ietf:params:oauth:token-type:jwt"));
        bodyElements.add(new BasicNameValuePair("principal_id", "9801000050702"));
        bodyElements.add(new BasicNameValuePair("person_id", "761337610411353650%5E%5E%5E%262.16.756.5.30.1.109.6.5.3.1.1%26ISO"));
        bodyElements.add(new BasicNameValuePair("principal_id", "9801000050702"));
        bodyElements.add(new BasicNameValuePair("scope", "user%2F*.*+openid+fhirUser+purpose_of_use%3Durn%3Aoid%3A2.16.756.5.30.1.127.3.10.5%7CAUTO+subject_role%3Durn%3Aoid%3A2.16.756.5.30.1.127.3.10.6%7CTC"));

        // create sha256 hash of body elements
        UrlEncodedFormEntity entity = new UrlEncodedFormEntity(bodyElements);

        String contentAsString = new String(entity.getContent().readAllBytes());
        byte[] contentDigestAsBytes = DigestUtils.sha512(contentAsString);
        String sha512Base64 = Base64.getEncoder().encodeToString(contentDigestAsBytes);

        // create the http request
        HttpClient httpClient = HttpClients.createDefault();

        HttpPost httpPost = new HttpPost(apiUrl);
        httpPost.addHeader("Content-Type", "application/x-www-form-urlencoded");

        String authZ = "Basic bXktYXBwOm15LWFwcC1zZWNyZXQtMTIz";
        httpPost.addHeader("Authorization", authZ);

        String contentDigest = "sha-512=:" + sha512Base64 + "=:";
        httpPost.addHeader("Content-Digest", contentDigest);

        httpPost.setEntity(entity);

        // sign the http request
        JWK signingKey = JWK.parse(SIGNING_KEY);
        Instant timestamp = Instant.now();

        // Create a signer and sign. The order of elements is important and
        // shall match the expected order on the server.
        FapiResourceRequestSigner signer = new FapiResourceRequestSigner()
                .setMethod("POST")
                .setTargetUri(URI.create(apiUrl))
                .setAuthorization(authZ)
                .setContentDigest(contentDigest)
                .setSigningKey(signingKey)
                .setCreated(timestamp);

        // Sign
        SigningInfo signingInfo = signer.sign();

        // add metadata header
        String signatureMetadata = signingInfo.getSerializedSignatureMetadata();
        String metadataHeaderValue = "sig1=" + signatureMetadata;
        httpPost.addHeader("Signature-Input", metadataHeaderValue);

        // add signature header
        String signature = signingInfo.getSerializedSignature();
        httpPost.addHeader("Signature", "sig1=" + signature);

        // call the remote token endpoint
        HttpResponse response = httpClient.execute(httpPost);

        BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
        StringBuilder result = new StringBuilder();

        String line;
        while ((line = reader.readLine()) != null) {
            result.append(line);
        }

        // TODO extract extension and scope
        Algorithm algorithm = Algorithm.HMAC512("your-secret-key");

        JWTVerifier verifier = JWT.require(algorithm)
                .acceptLeeway(1)   //1 sec for nbf and iat
                .acceptExpiresAt(5)   //5 secs for exp
                .build();

        DecodedJWT jwt = verifier.verify(result.toString());

        // decode payload
        Base64.Decoder decoder = Base64.getUrlDecoder();
        String payload = new String(decoder.decode(jwt.getPayload()));
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

}
