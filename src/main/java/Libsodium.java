import com.muquit.libsodiumjna.*;
import com.muquit.libsodiumjna.exceptions.SodiumLibraryException;
import org.apache.log4j.BasicConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;

public class Libsodium {

    private static Logger logger = LoggerFactory.getLogger(Libsodium.class);

    public static void main(String[] args) {

        BasicConfigurator.configure();

        String libraryPath = "C:/v143/dynamic/libsodium.dll";
        System.out.println("Library path in Windows: " + libraryPath);
        SodiumLibrary.setLibraryPath(libraryPath);

        String v = SodiumLibrary.libsodiumVersionString();
        System.out.println("libsodium version: " + v);

        byte[] randomBytes = SodiumLibrary.randomBytes(16);
        String hex = SodiumUtils.binary2Hex(randomBytes);
        System.out.println("Generate " + hex + " random bytes");

        // generate libsodium's standard number of salt bytes
        int n = SodiumLibrary.cryptoNumberSaltBytes();
        System.out.println("Generate " + n + " random bytes");
        byte[] salt = SodiumLibrary.randomBytes(n);
        System.out.println("Generated " + salt.length + " random bytes");
        String hex2 = SodiumUtils.binary2Hex(salt);
        System.out.println("Random bytes: " + hex2);

        // don't forget to load the libsodium library first

        String message = "This is a message";

        // generate nonce
        int nonceBytesLength = SodiumLibrary.cryptoSecretBoxNonceBytes().intValue();
        byte[] nonceBytes = SodiumLibrary.randomBytes(nonceBytesLength);
        byte[] messageBytes = message.getBytes();

        // generate the encryption key
        byte[] key = SodiumLibrary.randomBytes(SodiumLibrary.cryptoSecretBoxKeyBytes().intValue());
        System.out.println("key: " + key);

        // encrypt
        byte[] cipherText = new byte[0];

        try {
            cipherText = SodiumLibrary.cryptoSecretBoxEasy(messageBytes, nonceBytes, key);

            byte[] decryptedMessageBytes = SodiumLibrary.cryptoSecretBoxOpenEasy(cipherText, nonceBytes, key);
            String decryptedMessage;

            decryptedMessage = new String(decryptedMessageBytes, "UTF-8");
            System.out.println("Decrypted message: " + decryptedMessageBytes);
            System.out.println("Decrypted message: " + decryptedMessage);

        } catch (SodiumLibraryException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e)
        {
            e.printStackTrace();
        }

        System.out.println("============== Key Pair ============= ");

        try {

            SodiumKeyPair kp  = SodiumLibrary.cryptoBoxKeyPair();
            byte[] publicKey  = kp.getPublicKey();
            byte[] privateKey = kp.getPrivateKey();

            String hexPublicKey  = SodiumUtils.binary2Hex(publicKey);
            String hexPrivateKey = SodiumUtils.binary2Hex(privateKey);

            System.out.println("publicKey: " + publicKey);
            System.out.println("hexPublicKey: " + hexPublicKey);
            System.out.println("privateKey: " + privateKey);
            System.out.println("hexPrivateKey: " + hexPrivateKey);

            logger.error("error");

        } catch (SodiumLibraryException e) {
        throw new RuntimeException(e);
    }


    }
}
