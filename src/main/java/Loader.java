import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.pem.PemReader;
import sun.security.pkcs.PKCS8Key;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.KeySpec;

/**
 * Created by miranda on 7/13/2017.
 */
public class Loader {
    public String readFile(String filename) throws Exception {
        StringWriter stringWriter = new StringWriter();
        FileReader fileReader = new FileReader(filename);
        int c = fileReader.read();
        while (c != -1) {
            stringWriter.write(c);
            c = fileReader.read();
        }

        fileReader.close();
        return stringWriter.toString();
    }

    public byte[] readData(String filename) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        FileInputStream fileInputStream = new FileInputStream(filename);
        int b = fileInputStream.read();
        while (b != -1) {
            byteArrayOutputStream.write(b);
            b = fileInputStream.read();
        }
        fileInputStream.close();
        return byteArrayOutputStream.toByteArray();
    }


    public PrivateKey loadEncryptedPrivateKey(String filename, String password) throws Exception {
        FileReader fileReader = new FileReader(filename);
        PEMParser pemParser = new PEMParser(fileReader);
        PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) pemParser.readObject();
        PrivateKey key = new JcaPEMKeyConverter().setProvider("BC").getPrivateKey(
                pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(password.toCharArray())));

        return key;
    }

}
