import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SignatureException;
import java.util.HexFormat;

import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.crypto.StructuredDataEncoder;

/**
 * References:
 * - https://eips.ethereum.org/EIPS/eip-712
 * */
public class Ethereum {

  public static byte[] signTypedData(SignablePayload payload, byte[] privateKey) throws IOException {
    // Transforms the payload object into EIP-712 JSON, then serializes and hashes the payload
    final var encodedPayload = payload.encode();
    // Signs the message directly since the message is already a hash
    var signatureData = Sign.signMessage(encodedPayload, ECKeyPair.create(privateKey), false);

    return serializeSignatureData(signatureData);
  }

  public static boolean verifyTypedDataSignature(byte[] signature, SignablePayload payload, byte[] publicKey) throws IOException, SignatureException {
    // Converts to BigInteger to compare against the BigInteger key found by web3j
    var providedPublicKey = coercePublicKeyBytesToScalar(publicKey);

    // Reshapes signature to match web3j
    var signatureData = Sign.signatureDataFromHex(toHex(signature));
    // Identifies the public key used to sign the message
    var signingKey = Sign.signedMessageHashToKey(payload.encode(), signatureData);

    return providedPublicKey.equals(signingKey);
  }

  public static byte[] eip712Encode(String jsonData) throws IOException {
    StructuredDataEncoder dataEncoder = new StructuredDataEncoder(jsonData);
    return dataEncoder.hashStructuredData();
  }

  private static String toHex(byte[] data) {
    return HexFormat.of().formatHex(data);
  }

  private static BigInteger coercePublicKeyBytesToScalar(byte[] publicKey) {
    if (publicKey.length == 33) {
      throw new IllegalArgumentException("Compressed public keys are not supported");
    }

    return new BigInteger(1, publicKey);
  }

  /**
   * The signature consists of three components: r, s, and v: - `r` and `s` are outputs of the ECDSA
   * algorithm. - `v` is the recovery id, which helps in extracting the public key from the
   * signature.
   */
  private static byte[] serializeSignatureData(Sign.SignatureData data) {
    var signatureBuffer = ByteBuffer.allocate(65);

    // Concatenates the signature data byte arrays into a single one
    signatureBuffer.put(data.getR());
    signatureBuffer.put(data.getS());
    signatureBuffer.put(data.getV());

    return signatureBuffer.array();
  }
}
