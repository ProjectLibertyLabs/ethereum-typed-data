import java.io.IOException;

public interface SignablePayload {
  byte[] encode() throws IOException;
}
