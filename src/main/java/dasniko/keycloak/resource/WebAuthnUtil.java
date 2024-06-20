package dasniko.keycloak.resource;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

class WebAuthnUtil {
    public static byte[] base64UrlDecode(String input) {
        return Base64.getUrlDecoder().decode(input);
    }

    public static byte[] hash(String algorithm, byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        return digest.digest(data);
    }

    public static boolean verifySignature(PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }


}