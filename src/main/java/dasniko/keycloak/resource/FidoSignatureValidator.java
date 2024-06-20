package dasniko.keycloak.resource;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.upokecenter.cbor.CBORObject;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;

public class FidoSignatureValidator {


    public static boolean isValid(String cosePublicKeyBase64, String clientDataJSON,String authenticatorData,String signature) throws Exception {
        // Base64 encoded COSE CBOR public key
        /*
        String cosePublicKeyBase64 = "pQECAyYgASFYIC5kX1xUuGWqZjSRA-Ap3ElWHEEEekqgc2JSlutiAisnIlggakwsYu6fv-uLf59Aqv5gc9Sk0w4ZHu_7R26-PUaGdyg";

        String clientDataJSON = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiOERhNUd4RW1SQldkamdVNEV6X2FvUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTA5MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
        String authenticatorData = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA";
        String signature = "MEUCIQDT_u1dRGh8QXSRozorlMKc6ts8Os7RAaFpTjhoru3CAwIgBoe4FmhurQhatAljsrGeQY_XJLpgmvA37m7Ngi-Wv1Y";

        */
        // Decode the fields
        byte[] clientDataJSONBytes = WebAuthnUtil.base64UrlDecode(clientDataJSON);
        byte[] authenticatorDataBytes = WebAuthnUtil.base64UrlDecode(authenticatorData);
        byte[] signatureBytes = WebAuthnUtil.base64UrlDecode(signature);

        // Hash the clientDataJSON
        byte[] clientDataHash = WebAuthnUtil.hash("SHA-256", clientDataJSONBytes);

        // Concatenate authenticatorData and clientDataHash
        byte[] dataToVerify = new byte[authenticatorDataBytes.length + clientDataHash.length];
        System.arraycopy(authenticatorDataBytes, 0, dataToVerify, 0, authenticatorDataBytes.length);
        System.arraycopy(clientDataHash, 0, dataToVerify, authenticatorDataBytes.length, clientDataHash.length);

        // Retrieve the public key (this is an example, ensure you get the correct key for your user)
        PublicKey publicKey = getPublicKeyFromCredentialId2(cosePublicKeyBase64);

        // Verify the signature
        return WebAuthnUtil.verifySignature(publicKey, dataToVerify, signatureBytes);
    }

    /*


     */

    public static PublicKey getPublicKeyFromCredentialId2(String cosePublicKeyBase64) throws Exception {
        // Decode the Base64-url encoded COSE key
        byte[] cosePublicKeyBytes = Base64.getUrlDecoder().decode(cosePublicKeyBase64);

        // Parse the CBOR object
        CBORObject coseKeyCbor = CBORObject.DecodeFromBytes(cosePublicKeyBytes);

        // Extract key parameters
        byte[] xBytes = coseKeyCbor.get(CBORObject.FromObject(-2)).GetByteString();
        byte[] yBytes = coseKeyCbor.get(CBORObject.FromObject(-3)).GetByteString();

        // Ensure the x and y arrays are 32 bytes
        xBytes = ensure32Bytes(xBytes);
        yBytes = ensure32Bytes(yBytes);

        // Create ECPoint
        ECPoint ecPoint = new ECPoint(new java.math.BigInteger(1, xBytes), new java.math.BigInteger(1, yBytes));

        // Get EC Parameter Spec for P-256 curve
        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecSpec = parameters.getParameterSpec(ECParameterSpec.class);



        // Create ECPublicKeySpec
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecSpec);

        // Generate ECPublicKey
        return keyFactory.generatePublic(ecPublicKeySpec);
    }
    private static PublicKey getPublicKeyFromCredentialId(String cosePublicKeyBase64) throws JOSEException {


        // Decode the public key
        byte[] cosePublicKeyBytes = java.util.Base64.getUrlDecoder().decode(cosePublicKeyBase64);

        // Parse the CBOR object
        CBORObject coseKeyCbor = CBORObject.DecodeFromBytes(cosePublicKeyBytes);

        // Extract key parameters
        CBORObject keyType = coseKeyCbor.get(CBORObject.FromObject(1)); // Key type (kty)
        CBORObject keyCrv = coseKeyCbor.get(CBORObject.FromObject(-1)); // Curve (crv)
        CBORObject keyX = coseKeyCbor.get(CBORObject.FromObject(-2));   // X coordinate (x)
        CBORObject keyY = coseKeyCbor.get(CBORObject.FromObject(-3));   // Y coordinate (y)

        // Check if it's an EC key
        // Convert key parameters to Base64URL
        Base64URL xCoord = Base64URL.encode(keyX.GetByteString());
        Base64URL yCoord = Base64URL.encode(keyY.GetByteString());

        // Create ECKey from the parsed parameters
        ECKey ecKey = new ECKey.Builder(
                Curve.P_256, // Use appropriate curve
                xCoord,
                yCoord
        ).build();

        // Print the key
        System.out.println("EC Key: " + ecKey.toJSONString());


        return ecKey.toECPublicKey();






    }

    private static byte[] ensure32Bytes(byte[] bytes) {
        if (bytes.length == 32) {
            return bytes;
        } else if (bytes.length > 32) {
            // If the byte array is longer than 32 bytes, truncate it
            byte[] truncatedBytes = new byte[32];
            System.arraycopy(bytes, bytes.length - 32, truncatedBytes, 0, 32);
            return truncatedBytes;
        } else {
            // If the byte array is shorter than 32 bytes, pad it with leading zeros
            byte[] paddedBytes = new byte[32];
            System.arraycopy(bytes, 0, paddedBytes, 32 - bytes.length, bytes.length);
            return paddedBytes;
        }
    }


}
