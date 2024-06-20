package dasniko.keycloak.resource;


import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.util.Base64;
import java.util.List;

public class CosePublicKeyExtractor {
    public static void main(String[] args) {
        String coseEncodedPublicKey = "pQECAyYgASFYIEvYXEWCoEMCjOaCwx8S-G-NWPwL7wFgmoMuqD5g1b6PIlgg1LmaM2weqIJ5gowly5eIsOPxBCgHqiFU8cvb3qvk45o";
        byte[] publicKeyBytes = extractPublicKeyBytes(coseEncodedPublicKey);
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes);
        System.out.println("Public key (Base64): " + publicKeyBase64);
    }

    private static byte[] extractPublicKeyBytes(String coseEncodedPublicKey) {
        byte[] cosePublicKeyBytes = Base64.getUrlDecoder().decode(coseEncodedPublicKey);

        // Parse the CBOR object
        CBORObject coseKeyCbor = CBORObject.DecodeFromBytes(cosePublicKeyBytes);

        if (coseKeyCbor.getType() != CBORType.Array || coseKeyCbor.size() != 4) {
            throw new IllegalArgumentException("Invalid COSE public key format");
        }

        List<CBORObject> coseComponents = (List<CBORObject>) coseKeyCbor.getValues();

        // The second element in the array is the public key bytes
        byte[] publicKeyBytes = coseComponents.get(1).GetByteString();
        return publicKeyBytes;
    }
}
