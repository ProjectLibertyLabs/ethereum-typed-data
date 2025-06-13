import java.io.IOException;
import java.util.Arrays;

public record AddProviderPayload(
    String authorizedMsaId,
    int[] schemaIds,
    int expiration
) implements SignablePayload {

  @Override
  public byte[] encode() throws IOException {
    String schemaIdsJson = Arrays.toString(schemaIds);
    String jsonData = String.format(
      """
        {
          "types": {
            "EIP712Domain": [
              {
                "name": "name",
                "type": "string"
              },
              {
                "name": "version",
                "type": "string"
              },
              {
                "name": "chainId",
                "type": "uint256"
              },
              {
                "name": "verifyingContract",
                "type": "address"
              }
            ],
            "AddProvider": [
              {
                "name": "authorizedMsaId",
                "type": "uint64"
              },
              {
                "name": "schemaIds",
                "type": "uint16[]"
              },
              {
                "name": "expiration",
                "type": "uint32"
              }
            ]
          },
          "primaryType": "AddProvider",
          "domain": {
            "name": "Frequency",
            "version": "1",
            "chainId": "0x190f1b44",
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
          },
          "message": {
            "authorizedMsaId": "%s",
            "schemaIds": %s,
            "expiration": %d
          }
        }
      """.stripIndent(),
      authorizedMsaId,
      schemaIdsJson,
      expiration
    );

    return Ethereum.eip712Encode(jsonData);
  }
}
