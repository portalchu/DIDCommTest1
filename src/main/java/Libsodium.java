import com.goterl.lazysodium.SodiumJava;
import com.muquit.libsodiumjna.*;
import com.muquit.libsodiumjna.exceptions.SodiumLibraryException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.sun.jna.NativeLong;
import kotlin.sequences.Sequence;
import mock.DIDDocResolverMock;
import mock.SecretResolverInMemoryMock;
import org.didcommx.didcomm.DIDComm;
import org.didcommx.didcomm.crypto.key.Key;
import org.didcommx.didcomm.crypto.key.RecipientKeySelector;
import org.didcommx.didcomm.crypto.key.SenderKeySelector;
import org.didcommx.didcomm.message.Message;
import org.didcommx.didcomm.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
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

        logger.debug("Pack Message : " + packEncryptedResult.getPackedMessage());

        UnpackParams unpackParams = new UnpackParams.Builder(packEncryptedResult.getPackedMessage())
                .secretResolver(secretResolverInMemoryMock)
                .build();

        UnpackResult unpackResult = didComm.unpack(unpackParams);

        logger.debug("UnPack Message : " + unpackResult.getMessage().toString());

        logger.debug("========== Sign Test ==========");

        Message message2 = Message.Companion.builder(
                        "1234", body, "http://example.com/protocols/lets_do_lunch/1.0/proposal")
                .from(aliceDID)
                .to(to)
                .createdTime(1546521l)
                .expiresTime(1543215l)
                .build();

        logger.debug("Message : " + message2.toString());

        PackSignedParams packSignedParams = PackSignedParams.Companion.builder(message2, aliceDID)
                .build();

        PackSignedResult packSignedResult = didComm.packSigned(packSignedParams);

        logger.debug("Sign Message : " + packSignedResult.getPackedMessage());

        UnpackParams unpackParams2 = new UnpackParams.Builder(packSignedResult.getPackedMessage())
                .build();

        UnpackResult unpackResult2 = didComm.unpack(unpackParams2);

        logger.debug("UnPack Message : " + unpackResult2.getMessage().toString());
    }

    public void LibsodiumTestFun() {

        try {
            String libraryPath = "C:/v143/dynamic/libsodium.dll";
            System.out.println("Library path in Windows: " + libraryPath);
            SodiumLibrary.setLibraryPath(libraryPath);

            String v = SodiumLibrary.libsodiumVersionString();
            System.out.println("libsodium version: " + v);

            byte[] randomBytes = SodiumLibrary.randomBytes(32);
            String hex = SodiumUtils.binary2Hex(randomBytes);
            System.out.println("TT : Generate " + hex + " random bytes");

            String hexH1 = Base64.getEncoder().encodeToString(randomBytes);
            System.out.println("base : Generate " + hexH1 + " random bytes");

            byte[] randomBytesPair = SodiumLibrary.cryptoPublicKey(randomBytes);
            String hex3 = SodiumUtils.binary2Hex(randomBytesPair);
            System.out.println("TT : Generate " + hex3 + " random bytes");

            String hexH2 = Base64.getEncoder().encodeToString(randomBytesPair);
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

            System.out.println("============== Sign Key ============= ");

            int nonceBytesLength2 = SodiumLibrary.cryptoSecretBoxNonceBytes().intValue();
            byte[] nonceBytes2 = SodiumLibrary.randomBytes(nonceBytesLength2);
            byte[] messageBytes2 = message.getBytes();

            System.out.println("nonceBytesLength2: " + nonceBytesLength2);
            System.out.println("nonceBytes2: " + nonceBytes2);

// generate the encryption key
            byte[] key2 = SodiumLibrary.randomBytes(SodiumLibrary.cryptoSecretBoxKeyBytes().intValue());
            System.out.println("key2: " + key2);
            String basePrivateKey3 = Base64.getEncoder().encodeToString(key2);
            System.out.println("Base key2: " + basePrivateKey3);

// encrypt
            byte[] cipherText2 = SodiumLibrary.cryptoSecretBoxEasy(messageBytes2, nonceBytes2, key2);
            System.out.println("cipherText2: " + cipherText2);
            String baseCipherText2 = Base64.getEncoder().encodeToString(cipherText2);
            System.out.println("baseCipherText2: " + baseCipherText2);

// now decrypt
            byte[] decryptedMessageBytes2 = SodiumLibrary.cryptoSecretBoxOpenEasy(cipherText2, nonceBytes2, key2);
            String decryptedMessage2;
            decryptedMessage2 = new String(decryptedMessageBytes2, "UTF-8");
            System.out.println("Decrypted message: " + decryptedMessageBytes2);
            System.out.println("Decrypted message: " + decryptedMessage2);

            System.out.println("============== Sign Key 2 ============= ");

            SodiumKeyPair kps = SodiumLibrary.cryptoSignKeyPair();
            byte[] publicKeyS  = kps.getPublicKey();
            byte[] privateKeyS = kps.getPrivateKey();

            String hexPublicKeyS  = SodiumUtils.binary2Hex(publicKeyS);
            String basePublicKeyS = Base64.getEncoder().encodeToString(publicKeyS);
            String hexPrivateKeyS = SodiumUtils.binary2Hex(privateKeyS);
            String basePrivateKeyS = Base64.getEncoder().encodeToString(privateKeyS);

            System.out.println("publicKey: " + publicKeyS);
            System.out.println("hexPublicKey: " + hexPublicKeyS);
            System.out.println("privateKey: " + privateKeyS);
            System.out.println("hexPrivateKey: " + hexPrivateKeyS);
            System.out.println("basePublicKey: " + basePublicKeyS);
            System.out.println("basePrivateKey: " + basePrivateKeyS);

            byte[] privateKeyS2 = SodiumLibrary.cryptoSignEdSkTOcurveSk(privateKeyS);
            String hexPrivateKeySS = SodiumUtils.binary2Hex(privateKeyS2);
            String basePrivateKeySS = Base64.getEncoder().encodeToString(privateKeyS2);
            System.out.println("hexPrivateKey: " + hexPrivateKeySS);
            System.out.println("basePrivateKey: " + basePrivateKeySS);

            System.out.println("============== Key Generation ============= ");

            OctetKeyPair jwk = new OctetKeyPairGenerator(Curve.X25519)
                    .keyUse(KeyUse.ENCRYPTION) // indicate the intended use of the key
                    .keyID(UUID.randomUUID().toString()) // give the key a unique ID
                    .generate();

            byte[] jwkPublicKey = jwk.getDecodedX();
            byte[] jwkPrivateKey = jwk.getDecodedD();

            String testMessage = "Test123";

            byte[] jwkCrytoBox = SodiumLibrary.cryptoBoxEasy(
                    testMessage.getBytes(), nonceBytes, jwkPublicKey, jwkPrivateKey);

            System.out.println("jwkCrytoBox : " + SodiumUtils.binary2Hex(jwkCrytoBox));

            byte[] jwkCrytoOpenBox = SodiumLibrary.cryptoBoxOpenEasy(
                    jwkCrytoBox, nonceBytes, jwkPublicKey, jwkPrivateKey);

            System.out.println("jwkCrytoOpenBox : " + SodiumUtils.binary2Hex(jwkCrytoBox));
            System.out.println("jwkCrytoOpenBox : " + new String(jwkCrytoOpenBox));



            //SodiumLibrary.cryptoPublicKey()


            System.out.println("============== Sodium End ============= ");


        } catch (SodiumLibraryException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public void LazySodiumTest() {



        SodiumJava sodium = new SodiumJava();
    }

    public void NimbusdsTestFun() {

        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(Curve.P_256.toECParameterSpec());
            KeyPair keyPair = gen.generateKeyPair();

            JWK jwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
                    .privateKey((ECPrivateKey) keyPair.getPrivate())
                    .build();

            System.out.println("jwk: " + jwk);


            OctetKeyPair jwk2 = new OctetKeyPairGenerator(Curve.Ed25519)
                    .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
                    .keyID(UUID.randomUUID().toString()) // give the key a unique ID
                    .generate();

// Output the private and public OKP JWK parameters
            System.out.println(jwk2);

// Output the public OKP JWK parameters only
            System.out.println(jwk2.toPublicJWK());

            OctetKeyPair jwk3 = new OctetKeyPairGenerator(Curve.X25519)
                    .keyUse(KeyUse.ENCRYPTION) // indicate the intended use of the key
                    .keyID(UUID.randomUUID().toString()) // give the key a unique ID
                    .generate();

            System.out.println(jwk3);

            System.out.println(jwk3.toPublicJWK());

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch ( InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (JOSEException e) {
            e.printStackTrace();
        }

    }
}
