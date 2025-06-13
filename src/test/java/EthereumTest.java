import java.io.IOException;
import java.security.SignatureException;
import java.util.HexFormat;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.Bip32ECKeyPair;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.MnemonicUtils;

public class EthereumTest {

  final String seedPhrase = "click pepper grow cart estate tuition spy exact love kind evoke stage";
  final ECKeyPair keyPair = Bip32ECKeyPair.generateKeyPair(MnemonicUtils.generateSeed(seedPhrase, null));

  final AddProviderPayload payload = new AddProviderPayload("12876327", new int[] {2, 4, 5, 6, 7, 8}, 100);

  @Test
  public void signTypedDataAddProvider() throws IOException {
    // WHEN
    var signature = Ethereum.signTypedData(payload, keyPair.getPrivateKey().toByteArray());

    // THEN
    final var expectedSignature = HexFormat.of().parseHex(
        "a02bc642a606b4de2136d8c56adc374f88cde36111fe0d0ea15252c86c5a79df46a807fca48d06ec59c3833b2b92751b162452eac8eb3152a960ab7cb49e7fcc1b"
    );
    Assertions.assertArrayEquals(expectedSignature, signature);
  }

  @Test
  public void verifyTypedDataAddProvider() throws IOException, SignatureException {
    // GIVEN
    final var signature = Ethereum.signTypedData(payload, keyPair.getPrivateKey().toByteArray());

    // WHEN
    boolean isValid = Ethereum.verifyTypedDataSignature(signature, payload, keyPair.getPublicKey().toByteArray());

    // THEN
    Assertions.assertTrue(isValid);
  }
}
