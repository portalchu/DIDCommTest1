import com.goterl.lazysodium.SodiumJava;
import com.muquit.libsodiumjna.*;
import com.muquit.libsodiumjna.exceptions.SodiumLibraryException;
import com.sun.jna.NativeLong;
import kotlin.sequences.Sequence;
import mock.DIDDocResolverMock;
import mock.SecretResolverInMemoryMock;
import org.didcommx.didcomm.DIDComm;
import org.didcommx.didcomm.crypto.key.Key;
import org.didcommx.didcomm.crypto.key.RecipientKeySelector;
import org.didcommx.didcomm.crypto.key.SenderKeySelector;
import org.didcommx.didcomm.message.Message;
import org.didcommx.didcomm.model.PackEncryptedParams;
import org.didcommx.didcomm.model.PackEncryptedResult;
import org.didcommx.didcomm.model.UnpackParams;
import org.didcommx.didcomm.model.UnpackResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.util.*;

public class Libsodium {

    private static Logger logger = LoggerFactory.getLogger(Libsodium.class);

    public void DIDCommTestFun() {
        String aliceDID = "did:example:alice";
        String aliceDIDKey = "did:example:alice#key-1";

        DIDDocResolverMock didDocResolverMock = new DIDDocResolverMock();
        didDocResolverMock.SetDIDDoc();

        SecretResolverInMemoryMock secretResolverInMemoryMock = new SecretResolverInMemoryMock();
        secretResolverInMemoryMock.SetSecret();

        DIDComm didComm = new DIDComm(didDocResolverMock, secretResolverInMemoryMock);

        logger.debug("========== Key Test ==========");

        SenderKeySelector senderKeySelector = new SenderKeySelector(didDocResolverMock, secretResolverInMemoryMock);
        List<Key> keys = senderKeySelector.findAnonCryptKeys(aliceDID);

        for (Key key : keys) {
            logger.debug("Key : " + key.getId());
            logger.debug("Key : " + key.getJwk());
            logger.debug("Key : " + key.toString());
        }

        RecipientKeySelector recipientKeySelector = new RecipientKeySelector(didDocResolverMock, secretResolverInMemoryMock);
        List<String> testList = new ArrayList<String>();
        testList.add(aliceDIDKey);

        Sequence<Key> toKeys = recipientKeySelector.findAnonCryptKeys(testList);

        Iterator<Key> keyIter = toKeys.iterator();

        while (keyIter.hasNext()) {
            Key key = keyIter.next();
            logger.debug("Key : " + key.getId());
            logger.debug("Key : " + key.getJwk());
            logger.debug("Key : " + key.toString());
        }

        logger.debug("========== Key Test End ==========");

        Map<String, String> body = new HashMap<>();
        body.put("message", "Helo");

        List<String> to = new ArrayList<>();
        to.add(aliceDID);

        Message message = Message.Companion.builder(
                        "1234", body, "http://example.com/protocols/lets_do_lunch/1.0/proposal")
                .from(aliceDID)
                .to(to)
                .createdTime(1546521l)
                .expiresTime(1543215l)
                .build();

        logger.debug("Message : " + message.toString());

        PackEncryptedParams packEncryptedParams = PackEncryptedParams.Companion.builder(
                        message, aliceDID)
                .from(aliceDID)
                .build();

        PackEncryptedResult packEncryptedResult = didComm.packEncrypted(packEncryptedParams);

        logger.debug(packEncryptedResult.getPackedMessage());

        UnpackParams unpackParams = new UnpackParams.Builder(packEncryptedResult.getPackedMessage())
                .secretResolver(secretResolverInMemoryMock)
                .build();

        UnpackResult unpackResult = didComm.unpack(unpackParams);

        logger.debug(unpackResult.getMessage().toString());
    }

    public void LibsodiumTestFun() {

        try {
            String libraryPath = "C:/v143/dynamic/libsodium.dll";
            System.out.println("Library path in Windows: " + libraryPath);
            SodiumLibrary.setLibraryPath(libraryPath);

            String v = SodiumLibrary.libsodiumVersionString();
            System.out.println("libsodium version: " + v);

            byte[] randomBytes = SodiumLibrary.randomBytes(16);
            String hex = SodiumUtils.binary2Hex(randomBytes);
            System.out.println("TT : Generate " + hex + " random bytes");

            String hexH1 = Base64.getUrlEncoder().encodeToString(randomBytes);
            System.out.println("base : Generate " + hexH1 + " random bytes");

            byte[] randomBytesPair = SodiumLibrary.cryptoPublicKey(randomBytes);
            String hex3 = SodiumUtils.binary2Hex(randomBytesPair);
            System.out.println("TT : Generate " + hex3 + " random bytes");

            byte[] hexH2 = Base64.getEncoder().encode(randomBytesPair);
            System.out.println("base : Generate " + hexH2 + " random bytes");

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
            System.out.println("key: " + SodiumUtils.binary2Hex(key));

            // encrypt
            byte[] cipherText = new byte[0];

            cipherText = SodiumLibrary.cryptoSecretBoxEasy(messageBytes, nonceBytes, key);

            byte[] decryptedMessageBytes = SodiumLibrary.cryptoSecretBoxOpenEasy(cipherText, nonceBytes, key);
            String decryptedMessage;

            decryptedMessage = new String(decryptedMessageBytes, "UTF-8");
            System.out.println("Decrypted message: " + decryptedMessageBytes);
            System.out.println("Decrypted message: " + decryptedMessage);


            System.out.println("============== Key Pair ============= ");


            NativeLong number1 = SodiumLibrary.cryptoSecretBoxKeyBytes();
            logger.debug("SecretKey" + number1.toString());
            NativeLong number2 = SodiumLibrary.crytoBoxPublicKeyBytes();
            logger.debug("PublicKey" + number2.toString());

            SodiumKeyPair kp  = SodiumLibrary.cryptoBoxKeyPair();
            SodiumLibrary.cryptoBoxKeyPair();
            byte[] publicKey  = kp.getPublicKey();
            byte[] privateKey = kp.getPrivateKey();

            String hexPublicKey  = SodiumUtils.binary2Hex(publicKey);
            String basePublicKey = Base64.getEncoder().encodeToString(publicKey);
            String hexPrivateKey = SodiumUtils.binary2Hex(privateKey);
            String basePrivateKey = Base64.getEncoder().encodeToString(privateKey);

            System.out.println("publicKey: " + publicKey);
            System.out.println("hexPublicKey: " + hexPublicKey);
            System.out.println("privateKey: " + privateKey);
            System.out.println("hexPrivateKey: " + hexPrivateKey);
            System.out.println("basePublicKey: " + basePublicKey);
            System.out.println("basePrivateKey: " + basePrivateKey);


        } catch (SodiumLibraryException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public void LazySodiumTest() {



        SodiumJava sodium = new SodiumJava();
    }
}
