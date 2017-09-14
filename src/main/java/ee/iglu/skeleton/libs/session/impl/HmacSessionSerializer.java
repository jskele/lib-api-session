package ee.iglu.skeleton.libs.session.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import ee.iglu.skeleton.libs.session.ApiSessionSerializer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import static com.google.common.base.Preconditions.checkArgument;
import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
@Component
@RequiredArgsConstructor
class HmacSessionSerializer implements ApiSessionSerializer {

    private final Clock clock;
    private final ObjectMapper objectMapper;
    private final HashFunction tokenSigner;

    private final Decoder decoder = Base64.getUrlDecoder();
    private final Encoder encoder = Base64.getUrlEncoder().withoutPadding();

    @Override
    public String writeAsToken(Object session) {
        Instant expires = clock.instant().plus(Duration.ofDays(356));
        try {
            String headerString = createEncodedString(expires.getEpochSecond());
            String payloadString = createEncodedString(session);

            String contentString = join(headerString, payloadString);
            String signatureEncoded = createSignatureString(contentString);

            return join(signatureEncoded, contentString);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private String join(String string1, String string2) {
        return string1 + "." + string2;
    }

    private String[] split(String string) {
        String[] split = string.split("\\.", 2);
        checkArgument(split.length == 2, "malformed token");
        return split;
    }

    private String createEncodedString(Object value) throws JsonProcessingException {
        byte[] bytes = objectMapper.writeValueAsBytes(value);
        return encoder.encodeToString(bytes);
    }

    @Override
    public <T> T readFromToken(String token, Class<T> sessionClass) {
        if (token == null) {
            return null;
        }

        String[] signatureAndContent = split(token);
        String signatureString = signatureAndContent[0];
        String contentString = signatureAndContent[1];
        checkSignature(signatureString, contentString);

        String[] headerAndPayload = split(contentString);
        String headerString = headerAndPayload[0];
        String payloadString = headerAndPayload[1];
        try {
            checkHeader(headerString);
            return readPayload(payloadString, sessionClass);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String createSignatureString(String contentString) {
        HashCode signature = tokenSigner.hashString(contentString, UTF_8);
        byte[] signatureBytes = signature.asBytes();
        return encoder.encodeToString(signatureBytes);
    }

    private void checkSignature(String signatureString, String contentString) {
        String expectedSignatureString = createSignatureString(contentString);
        byte[] actualBytes = signatureString.getBytes(UTF_8);
        byte[] expectedBytes = expectedSignatureString.getBytes(UTF_8);

        boolean equal = MessageDigest.isEqual(actualBytes, expectedBytes);
        checkArgument(equal, "signature mismatch");
    }

    private void checkHeader(String headerString) throws IOException {
        byte[] headerBytes = decoder.decode(headerString);
        Long expiresEpochSeconds = objectMapper.readValue(headerBytes, Long.class);
        Instant expires = Instant.ofEpochSecond(expiresEpochSeconds);
        Duration expiresIn = Duration.between(clock.instant(), expires);

        boolean expired = expiresIn.isNegative();
        checkArgument(!expired, "token expired %s seconds ago", expiresIn.getSeconds());
    }

    private <T> T readPayload(String sessionString, Class<T> sessionClass) throws IOException {
        byte[] jsonBytes = decoder.decode(sessionString);
        return objectMapper.readValue(jsonBytes, sessionClass);
    }

}
