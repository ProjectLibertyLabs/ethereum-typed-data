import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.ECKeyPair;

import java.io.IOException;
import java.security.SignatureException;
import java.util.HexFormat;

/**
 * Test data lifted from https://github.com/frequency-chain/frequency/blob/bac7782cba59247c7f89c0208720335a1289b8ce/js/ethereum-utils/test/signature.test.ts#L237
 */
public class FrequencyCompatibilityTest {

  private final byte[] privateKey = HexFormat.of().parseHex("5fb92d6e98884f76de468fa3f6278f8807c48bebc13595d45af5bdc4da702133");
  private final byte[] publicKeyBytes = ECKeyPair.create(privateKey).getPublicKey().toByteArray();

  private final AddProviderPayload payload = new AddProviderPayload("12876327", new int[] {2, 4, 5, 6, 7, 8}, 100);

  @Test
  public void signTypedDataAddProvider() throws IOException {
    // WHEN
    var signature = Ethereum.signTypedData(payload, privateKey);

    // THEN
    final var expectedSignature = HexFormat.of().parseHex(
        "34ed5cc291815bdc7d95b418b341bbd3d9ca82c284d5f22d8016c27bb9d4eef8507cdb169a40e69dc5d7ee8ff0bff29fa0d8fc4e73cad6fc9bf1bf076f8e0a741c"
    );
    Assertions.assertArrayEquals(expectedSignature, signature);
  }

  @Test
  public void verifyTypedDataAddProvider() throws IOException, SignatureException {
    // GIVEN
    final var signature = HexFormat.of().parseHex(
        "34ed5cc291815bdc7d95b418b341bbd3d9ca82c284d5f22d8016c27bb9d4eef8507cdb169a40e69dc5d7ee8ff0bff29fa0d8fc4e73cad6fc9bf1bf076f8e0a741c"
    );

    // WHEN
    boolean isValid = Ethereum.verifyTypedDataSignature(signature, payload, publicKeyBytes);

    // THEN
    Assertions.assertTrue(isValid);
  }
}
