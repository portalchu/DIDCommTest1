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

        logger.debug("========== DIDComm Test ==========");

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



        logger.debug("========== Encrypted Test End ==========");

        Map<String, String> body = new HashMap<>();
        body.put("message", "Hello World");

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

        Map<String, String> body2 = new HashMap<>();
        body2.put("message", "Hello World");

        List<String> to2 = new ArrayList<>();
        to2.add(aliceDID);

        Message message2 = Message.Companion.builder(
                        "1234", body2, "http://example.com/protocols/lets_do_lunch/1.0/proposal")
                .from(aliceDID)
                .to(to2)
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

            byte[] signMessage = SodiumLibrary.cryptoSign(messageBytes, privateKey);
            System.out.println("signMessage : " + Base64.getEncoder().encodeToString(signMessage));

            byte[] signMessageOpen = SodiumLibrary.cryptoSignOpen(signMessage, publicKey);
            System.out.println("signMessageOpen : " + new String(signMessageOpen));

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

            byte[] privateKeyC = SodiumLibrary.cryptoSignEdSkTOcurveSk(privateKeyS);
            byte[] publicKeyC = SodiumLibrary.cryptoSignEdPkTOcurvePk(publicKeyS);
            String basePrivateKeyC = Base64.getEncoder().encodeToString(privateKeyC);
            String basePublicKeyC = Base64.getEncoder().encodeToString(publicKeyC);
            System.out.println("basePublicKeyC: " + basePublicKeyC);
            System.out.println("basePrivateKeyC: " + basePrivateKeyC);

            System.out.println("============== Key Generation ============= ");

            OctetKeyPair jwk = new OctetKeyPairGenerator(Curve.X25519)
                    .keyUse(KeyUse.ENCRYPTION) // indicate the intended use of the key
                    .keyID(UUID.randomUUID().toString()) // give the key a unique ID
                    .generate();

            OctetKeyPair jwk2 = new OctetKeyPairGenerator(Curve.Ed25519)
                    .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
                    .keyID(UUID.randomUUID().toString()) // give the key a unique ID
                    .generate();

            byte[] jwkPublicKey = jwk.getDecodedX();
            byte[] jwkPrivateKey = jwk.getDecodedD();

            String testMessage = "Test123";
            byte[] testMessageByte = testMessage.getBytes();

            byte[] jwkCrytoBox = SodiumLibrary.cryptoBoxEasy(
                    testMessage.getBytes(), nonceBytes, jwkPublicKey, jwkPrivateKey);

            System.out.println("jwkCrytoBox : " + SodiumUtils.binary2Hex(jwkCrytoBox));

            byte[] jwkCrytoOpenBox = SodiumLibrary.cryptoBoxOpenEasy(
                    jwkCrytoBox, nonceBytes, jwkPublicKey, jwkPrivateKey);

            System.out.println("jwkCrytoOpenBox : " + SodiumUtils.binary2Hex(jwkCrytoBox));
            System.out.println("jwkCrytoOpenBox : " + new String(jwkCrytoOpenBox));

            byte[] sodiumPrivateKey = SodiumLibrary.randomBytes(SodiumLibrary.cryptoSecretBoxKeyBytes().intValue());
            System.out.println("sodiumPrivateKey: " + Base64.getEncoder().encodeToString(sodiumPrivateKey));

            byte[] authMessage = SodiumLibrary.cryptoAuth(testMessageByte, sodiumPrivateKey);
            System.out.println("authMessage: " + Base64.getEncoder().encodeToString(authMessage));

            //boolean authCheck = SodiumLibrary.cryptoAuthVerify(authMessage, sodiumPrivateKey);

            byte[] edKeyCheck_S = SodiumLibrary.cryptoSignEdSkTOcurveSk(privateKey);
            //byte[] edKeyCheck_P = SodiumLibrary.cryptoSignEdPkTOcurvePk(publicKey);

            String edKeyBase_S = Base64.getEncoder().encodeToString(edKeyCheck_S);
            //String edKeyBase_P = Base64.getEncoder().encodeToString(edKeyCheck_P);

            System.out.println("edKeyCheck_S: " + edKeyBase_S);
            //System.out.println("edKeyCheck_P: " + edKeyBase_P);

            byte[] signMessage1 = SodiumLibrary.cryptoSign(testMessageByte, privateKey);
            System.out.println("SignMessage: " + Base64.getEncoder().encodeToString(signMessage1));

            byte[] signMessageCheck1 = SodiumLibrary.cryptoSignOpen(signMessage1, publicKey);
            System.out.println("SignOpenMessage: " + new String(signMessageCheck1));

            byte[] signMessage2 = SodiumLibrary.cryptoSign(testMessageByte, privateKeyC);
            System.out.println("SignMessage: " + Base64.getEncoder().encodeToString(signMessage2));

            byte[] signMessageCheck2 = SodiumLibrary.cryptoSignOpen(signMessage2, publicKeyC);
            System.out.println("SignOpenMessage: " + new String(signMessageCheck2, "UTF-8"));

            //SodiumLibrary.cryptoPublicKey()

            System.out.println("============== JWK Test2 ============= ");

            System.out.println("jwk2 Ed25519 : " + jwk2.toString());
            System.out.println("jwk2 Ed25519 PK : " + jwk2.getX());
            System.out.println("jwk2 Ed25519 SK : " + jwk2.getD());

            kps.setPrivateKey(jwk2.getDecodedD());
            kps.setPublicKey(jwk2.getDecodedX());
            System.out.println("kps Ed25519 PK : " + Base64.getEncoder().encodeToString(kps.getPublicKey()));
            System.out.println("kps Ed25519 SK : " + Base64.getEncoder().encodeToString(kps.getPrivateKey()));

            byte[] signMessage3 = SodiumLibrary.cryptoSign(testMessageByte, kps.getPrivateKey());
            System.out.println("SignMessage: " + Base64.getEncoder().encodeToString(signMessage3));

            byte[] signMessageCheck3 = SodiumLibrary.cryptoSignOpen(signMessage3, kps.getPublicKey());
            System.out.println("SignOpenMessage: " + new String(signMessageCheck3));



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

        System.out.println("============== JWK Test =============");

        try {

            System.out.println("============== JWK P_256 Test =============");

            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(Curve.P_256.toECParameterSpec());
            KeyPair keyPair = gen.generateKeyPair();

            JWK jwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
                    .privateKey((ECPrivateKey) keyPair.getPrivate())
                    .build();

            System.out.println("jwk: " + jwk);

            System.out.println("============== JWK P_384 Test =============");

            KeyPairGenerator gen4 = KeyPairGenerator.getInstance("EC");
            gen4.initialize(Curve.P_384.toECParameterSpec());
            KeyPair keyPair4 = gen4.generateKeyPair();

            JWK jwk4 = new ECKey.Builder(Curve.P_384, (ECPublicKey) keyPair4.getPublic())
                    .privateKey((ECPrivateKey) keyPair4.getPrivate())
                    .build();

            System.out.println("jwk: " + jwk4);

            System.out.println("============== JWK P_521 Test =============");

            KeyPairGenerator gen5 = KeyPairGenerator.getInstance("EC");
            gen5.initialize(Curve.P_521.toECParameterSpec());
            KeyPair keyPair5 = gen5.generateKeyPair();

            JWK jwk5 = new ECKey.Builder(Curve.P_521, (ECPublicKey) keyPair5.getPublic())
                    .privateKey((ECPrivateKey) keyPair5.getPrivate())
                    .build();

            System.out.println("jwk: " + jwk5);

            System.out.println("============== JWK SECP256K1 Test =============");

            KeyPairGenerator gen6 = KeyPairGenerator.getInstance("EC");
            gen6.initialize(Curve.SECP256K1.toECParameterSpec());
            KeyPair keyPair6 = gen6.generateKeyPair();

            JWK jwk6 = new ECKey.Builder(Curve.SECP256K1, (ECPublicKey) keyPair6.getPublic())
                    .privateKey((ECPrivateKey) keyPair6.getPrivate())
                    .build();

            System.out.println("jwk: " + jwk6);

            /*
            System.out.println("============== JWK X448 Test =============");

            KeyPairGenerator gen7 = KeyPairGenerator.getInstance("EC");
            gen7.initialize(Curve.X448.toECParameterSpec());
            KeyPair keyPair7 = gen7.generateKeyPair();

            JWK jwk7 = new ECKey.Builder(Curve.X448, (ECPublicKey) keyPair7.getPublic())
                    .privateKey((ECPrivateKey) keyPair7.getPrivate())
                    .build();

            System.out.println("jwk: " + jwk7);


             */

            System.out.println("============== JWK Ed25519 Test =============");

            OctetKeyPair jwk2 = new OctetKeyPairGenerator(Curve.Ed25519)
                    .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
                    .keyID(UUID.randomUUID().toString()) // give the key a unique ID
                    .generate();

            System.out.println(jwk2);

            System.out.println(jwk2.toPublicJWK());

            System.out.println("============== JWK X25519 Test =============");

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
