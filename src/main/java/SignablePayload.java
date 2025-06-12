import java.io.IOException;

public sealed interface SignablePayload permits AddProviderPayload {
  byte[] encode() throws IOException;
}
