package mock;

import org.didcommx.didcomm.common.VerificationMaterial;
import org.didcommx.didcomm.common.VerificationMaterialFormat;
import org.didcommx.didcomm.common.VerificationMethodType;
import org.didcommx.didcomm.diddoc.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class DIDDocResolverMock implements DIDDocResolver {

    private DIDDoc didDoc1;
    private List<DIDDoc> didDocList = new ArrayList<>();

    public DIDDocResolverInMemory didDocResolverInMemory;

    public void SetDIDDoc() {
        VerificationMethod AliceMethod = new VerificationMethod(
                "did:example:alice#key-1",
                VerificationMethodType.JSON_WEB_KEY_2020,
                new VerificationMaterial(
                        VerificationMaterialFormat.JWK,
                        "{\"kty\":\"OKP\"," +
                                "\"crv\":\"Ed25519\"," +
                                "\"x\":\"1eESIYXnbLGwyNPeH0Nwxasd7exQJR2UD1OBGqoZDcg\"}"
                ),
                "did:example:alice#key-1"
        );

        VerificationMethod AliceMethod1 = new VerificationMethod(
                "did:example:alice#key-2",
                VerificationMethodType.JSON_WEB_KEY_2020,
                new VerificationMaterial(
                        VerificationMaterialFormat.JWK,
                        "{\"kty\":\"OKP\"," +
                                "\"crv\":\"X25519\"," +
                                "\"x\":\"F0g1QxzOMqTo00hg6PIf4zHY0_6FMe_OBujYsenYz3Q\"}"
                ),
                "did:example:alice#key-2"
        );

        VerificationMethod AliceMethod2 = new VerificationMethod(
                "did:example:alice#key-3",
                VerificationMethodType.JSON_WEB_KEY_2020,
                new VerificationMaterial(
                        VerificationMaterialFormat.JWK,
                        "{\"kty\":\"EC\"," +
                                "\"crv\":\"P-256\"," +
                                "\"x\":\"ivYUvybjaokTJantAbzGg96L4qkCjngDbliNp3yPkzM\"," +
                                "\"y\":\"ZtMsrzFOx-kdqQd_jJc2TnN_ASFJc2m0C7R2VhkfSJs\"}"
                ),
                "did:example:alice#key-3"
        );

        VerificationMethod AliceMethod3 = new VerificationMethod(
                "did:example:alice#key-4",
                VerificationMethodType.JSON_WEB_KEY_2020,
                new VerificationMaterial(
                        VerificationMaterialFormat.JWK,
                        "{\"kty\":\"EC\"," +
                                "\"crv\":\"P-384\"," +
                                "\"x\":\"wKqfYznOMAtdHuMfzn3kxSXj-em2PHnzBRwalbJZRVfnrvO5zMgpwL0cvBw89QML\"," +
                                "\"y\":\"QLmGVThWGUF3yOo1WdBuuepKygs4xOnpZErxJrp33UjST8uaF75l7RR5YdDcuxPs\"}"
                ),
                "did:example:alice#key-4"
        );

        VerificationMethod AliceMethod4 = new VerificationMethod(
                "did:example:alice#key-5",
                VerificationMethodType.JSON_WEB_KEY_2020,
                new VerificationMaterial(
                        VerificationMaterialFormat.JWK,
                        "{\"kty\":\"EC\"," +
                                "\"crv\":\"P-521\"," +
                                "\"x\":\"AdhTtFmjcApJOXNNH9DASL1V6_q3Vs_PUVX-5HxVMywPtX7dAO02_kUBej4Wf7hbwNXktnAkn-YXrOohGQ9IBMPS\"," +
                                "\"y\":\"AaG7be12d_uptxBUL1p9cey0TRTR5mxVMfe8OxZUjrRUgFmguBzEKUgPIIG9WQofvbjKxPcLVjHrPwGBH8QsHmcW\"}"
                ),
                "did:example:alice#key-5"
        );

        VerificationMethod AliceMethod6 = new VerificationMethod(
                "did:example:alice#key-6",
                VerificationMethodType.JSON_WEB_KEY_2020,
                new VerificationMaterial(
                        VerificationMaterialFormat.JWK,
                        "{\"kty\":\"EC\"," +
                                "\"crv\":\"secp256k1\"," +
                                "\"x\":\"YtMKHzQ7XfvEXGE_XvDNPYxhdvOGZes0UlNqkzXUNSM\"," +
                                "\"y\":\"M37EnuxZv85ucjHINqKadm9Y84t97hn8P5KRyxZIlmE\"}"
                ),
                "did:example:alice#key-6"
        );

        List<VerificationMethod> verificationMethodList = new ArrayList<>();
        verificationMethodList.add(AliceMethod);
        verificationMethodList.add(AliceMethod1);
        verificationMethodList.add(AliceMethod2);
        verificationMethodList.add(AliceMethod3);
        verificationMethodList.add(AliceMethod4);
        verificationMethodList.add(AliceMethod6);

        List<DIDCommService> didCommServiceList = new ArrayList<>();

        List<String> keyAgreementList = new ArrayList<>();
        keyAgreementList.add("did:example:alice#key-2");
        keyAgreementList.add("did:example:alice#key-3");
        keyAgreementList.add("did:example:alice#key-4");
        keyAgreementList.add("did:example:alice#key-5");

        List<String> authentications = new ArrayList<>();
        //authentications.add("did:example:alice#key-1");
        //authentications.add("did:example:alice#key-3");
        authentications.add("did:example:alice#key-6");

        didDoc1 = new DIDDoc(
                "did:example:alice",
                keyAgreementList,
                authentications,
                verificationMethodList,
                didCommServiceList
        );

        didDocList.add(didDoc1);

        didDocResolverInMemory = new DIDDocResolverInMemory(didDocList);
    }

    @Override
    public Optional<DIDDoc> resolve(String did) {
        return didDocResolverInMemory.resolve(did);
    }
}
