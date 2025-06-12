import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.Bip32ECKeyPair;
import org.web3j.crypto.ECKeyPair;

import java.util.HexFormat;

public class EthereumTest {

  /**
   * Test data lifted from https://github.com/frequency-chain/frequency/blob/bac7782cba59247c7f89c0208720335a1289b8ce/js/ethereum-utils/test/signature.test.ts#L237
   */
  @Test
  public void signTypedDataAddProvider() {
    // GIVEN
    final var privateKey = HexFormat.of().parseHex("5fb92d6e98884f76de468fa3f6278f8807c48bebc13595d45af5bdc4da702133");
    final var payload = new AddProviderPayload("12876327", new int[] {2, 4, 5, 6, 7, 8}, 100);

    // WHEN
    var signature = new byte[0];
    try {
      signature = Ethereum.signTypedData(payload, privateKey);
    } catch (final Exception e) {
      Assertions.fail(e.getMessage());
    }

    // THEN
    final var expectedSignature = HexFormat.of().parseHex(
        "34ed5cc291815bdc7d95b418b341bbd3d9ca82c284d5f22d8016c27bb9d4eef8507cdb169a40e69dc5d7ee8ff0bff29fa0d8fc4e73cad6fc9bf1bf076f8e0a741c"
    );
    Assertions.assertArrayEquals(expectedSignature, signature);
  }

  /**
   * Test data lifted from https://github.com/frequency-chain/frequency/blob/bac7782cba59247c7f89c0208720335a1289b8ce/js/ethereum-utils/test/signature.test.ts#L237
   */
  @Test
  public void verifyTypedDataAddProvider() {
    // GIVEN
    final var privateKey = HexFormat.of().parseHex("5fb92d6e98884f76de468fa3f6278f8807c48bebc13595d45af5bdc4da702133");
    final var keyPair = ECKeyPair.create(privateKey);
    final var payload = new AddProviderPayload("12876327", new int[] {2, 4, 5, 6, 7, 8}, 100);
    final var signature = HexFormat.of().parseHex(
        "34ed5cc291815bdc7d95b418b341bbd3d9ca82c284d5f22d8016c27bb9d4eef8507cdb169a40e69dc5d7ee8ff0bff29fa0d8fc4e73cad6fc9bf1bf076f8e0a741c"
    );

    // WHEN
    boolean isValid = false;
    try {
      isValid = Ethereum.verifyTypedDataSignature(signature, payload, keyPair.getPublicKey().toByteArray());
    } catch (final Exception e) {
      Assertions.fail(e.getMessage());
    }

    // THEN
    Assertions.assertTrue(isValid);
  }
}
