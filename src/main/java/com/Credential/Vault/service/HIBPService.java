
package com.Credential.Vault.service;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;

@Service
public class HIBPService {

    private static final String API_URL =
            "https://api.pwnedpasswords.com/range/";

    private final HttpClient httpClient;

    public HIBPService() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public record BreachResult(
            boolean breached,
            long occurrences
    ) {}

    public BreachResult checkPassword(String password) {

        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException(
                    "Password cannot be empty"
            );
        }

        try {
            // 1. Generate SHA-1 hash locally.
            String hash = generateSHA1(password);

            // 2. Split hash into prefix and suffix.
            String prefix = hash.substring(0, 5);
            String suffix = hash.substring(5);

            // 3. Send only the first 5 characters.
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API_URL + prefix))
                    .timeout(Duration.ofSeconds(20))
                    .header("User-Agent", "SecureVault/1.0")
                    .header("Add-Padding", "true")
                    .GET()
                    .build();

            HttpResponse<String> response =
                    httpClient.send(
                            request,
                            HttpResponse.BodyHandlers.ofString()
                    );

            if (response.statusCode() != 200) {
                throw new IllegalStateException(
                        "HIBP API returned status: "
                                + response.statusCode()
                );
            }

            // 4. Compare returned suffix locally.
            for (String line : response.body().split("\\r?\\n")) {

                String[] parts = line.split(":");

                if (parts.length != 2) {
                    continue;
                }

                String returnedSuffix = parts[0].trim();

                long count;

                try {
                    count = Long.parseLong(parts[1].trim());
                } catch (NumberFormatException ex) {
                    continue;
                }

                if (count > 0 &&
                        returnedSuffix.equalsIgnoreCase(suffix)) {

                    return new BreachResult(true, count);
                }
            }

            // 5. No matching password found.
            return new BreachResult(false, 0);

        } catch (NoSuchAlgorithmException | IOException ex) {

            throw new IllegalStateException(
                    "Unable to check password against HIBP",
                    ex
            );

        } catch (InterruptedException ex) {

            Thread.currentThread().interrupt();

            throw new IllegalStateException(
                    "HIBP request was interrupted",
                    ex
            );
        }
    }

    private String generateSHA1(String password)
            throws NoSuchAlgorithmException {

        MessageDigest digest =
                MessageDigest.getInstance("SHA-1");

        byte[] hashBytes = digest.digest(
                password.getBytes(StandardCharsets.UTF_8)
        );

        return HexFormat.of()
                .withUpperCase()
                .formatHex(hashBytes);
    }
}
