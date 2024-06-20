package dasniko.keycloak.resource;

import lombok.*;

@Data
@Builder
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class FidoRequestSignatureValidator {
private  String clientDataJSON;
    private  String authenticatorData;
    private  String signature;
}
