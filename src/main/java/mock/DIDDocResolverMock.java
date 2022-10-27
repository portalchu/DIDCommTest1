package mock;

import org.didcommx.didcomm.common.VerificationMaterial;
import org.didcommx.didcomm.common.VerificationMaterialFormat;
import org.didcommx.didcomm.common.VerificationMethodType;
import org.didcommx.didcomm.diddoc.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class DIDDocResolverMock implements DIDDocResolver {

    public VerificationMethod AliceMethod;

    private DIDDoc didDoc1;
    private List<DIDDoc> didDocList = new ArrayList<>();

    public DIDDocResolverInMemory didDocResolverInMemory;

    public void SetDIDDoc() {
        AliceMethod = new VerificationMethod(
                "did:example:alice#key-1",
                VerificationMethodType.JSON_WEB_KEY_2020,
                new VerificationMaterial(
                        VerificationMaterialFormat.JWK,
                        "{\"kty\":\"OKP\"," +
                                "\"crv\":\"Ed25519\"," +
                                "\"x\":\"hcVNRzH7mQArc+o1Tf9zHOh85xj+EdIFglZQYYEaoEA=\"}"
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
                                "\"x\":\"qCNxmHo8okIehEck/YX+/KLU07ySk0OGxe91FT4wLBE=\"}"
                ),
                "did:example:alice#key-2"
        );

        List<VerificationMethod> verificationMethodList = new ArrayList<>();
        verificationMethodList.add(AliceMethod);
        verificationMethodList.add(AliceMethod1);

        List<DIDCommService> didCommServiceList = new ArrayList<>();

        List<String> keyAgreementList = new ArrayList<>();
        keyAgreementList.add("did:example:alice#key-2");

        List<String> authentications = new ArrayList<>();
        authentications.add("did:example:alice#key-1");

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
