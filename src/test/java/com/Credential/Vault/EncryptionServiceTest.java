
package com.Credential.Vault;
import java.util.Base64;
import com.Credential.Vault.service.EncryptionService;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionServiceTest {

    @Test
    void shouldEncryptAndDecrypt() {

        EncryptionService service = new EncryptionService();

        String original = "MySecret123!";

        String encrypted = service.encrypt(original);
        String decrypted = service.decrypt(encrypted);

        assertNotEquals(original, encrypted);
        assertEquals(original, decrypted);
    }

    @Test
    void shouldGenerateDifferentCiphertext() {

        EncryptionService service = new EncryptionService();

        String first = service.encrypt("MySecret123!");
        String second = service.encrypt("MySecret123!");

        assertNotEquals(first, second);
    }

    @Test
    void shouldRejectModifiedData() {

        EncryptionService service = new EncryptionService();

        String encrypted = service.encrypt("MySecret123!");

        byte[] bytes = Base64.getDecoder().decode(encrypted);
        bytes[bytes.length - 1] ^= 1;

        String modified = Base64.getEncoder()
                .encodeToString(bytes);

        assertThrows(
                IllegalStateException.class,
                () -> service.decrypt(modified)
        );
    }
}
