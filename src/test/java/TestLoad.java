import org.junit.Test;

import java.security.PrivateKey;

/**
 * Created by miranda on 7/13/2017.
 */
public class TestLoad {

    @Test
    public void testLoad () throws Exception {
        Loader loader = new Loader();
        PrivateKey privateKey = loader.loadEncryptedPrivateKey("ca-key.pem.txt", "whatever");
    }
}
