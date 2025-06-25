import * as transmute from '@transmute/verifiable-credentials';
import { resolver } from './resolverWithcache';
import { checkRevocationStatus } from './revocation';

export async function verifyVP(presentationJwtOrObj: string | object) {
  // Create validator with resolver
  const validator = transmute.validator({
    resolver: {
      resolve: async ({ type, id, content }) => resolver.resolve({ type,id, content })
    }
  });

  // 1. Verify VP structure and signature
  const vpResult = await validator.validate({
    type: 'application/vp-ld+jwt',
    content: typeof presentationJwtOrObj === 'string' 
      ? transmute.text.encoder.encode(presentationJwtOrObj)
      : transmute.text.encoder.encode(JSON.stringify(presentationJwtOrObj))
  });


  // 2. Extract and verify embedded credentials
  const credentialResults = [];
  let allCredentialsValid = true;

  if (vpResult.content?.verifiableCredential) {
    for (const [index, vc] of vpResult.content.verifiableCredential.entries()) {
      let vcContent: Uint8Array;
      let vcType: 'application/vc-ld+jwt' | 'application/vc-ld+sd-jwt' | 'application/vc-ld+cose' | 'application/vp-ld' | 'application/vp-ld+sd-jwt' | 'application/vp-ld+cose' | 'application/jwt' | 'application/kb+jwt' | 'application/sd-jwt';

      // Handle different VC formats
      if (typeof vc === 'string') {
        vcType = 'application/vc-ld+jwt';
        vcContent = transmute.text.encoder.encode(vc);
      } else if (vc?.id?.startsWith('data:application/vc-ld+jwt;')) {
        // Extract JWT from data URI
        const jwt = vc.id.split(';')[1];
        vcType = 'application/vc-ld+jwt';
        vcContent = transmute.text.encoder.encode(jwt);
      } else {
        // Handle JSON-LD credentials
        vcType = 'application/vc-ld+jwt';
        vcContent = transmute.text.encoder.encode(JSON.stringify(vc));
      }

      // Verify credential signature and structure
      const vcValidation = await validator.validate({
        type: vcType,
        content: vcContent
      });
      console.log(`\n=== Credential ${index} Verification ===`);
      
      // 1. Log signature verification
      console.log(`Signature Verified: ${vcValidation.verified}`);

      if (vcValidation.schema) {
        Object.entries(vcValidation.schema).forEach(([schemaId, schemaResult]) => {
          console.log(`Schema ${schemaId}: ${schemaResult.validation === "succeeded" ? "Valid" : "Invalid"}`);
        });
      } else {
        console.log("Schema Validation: Not performed");
      }

      // Check revocation for JWT credentials
      let revoked = false;
      if (vcType === 'application/vc-ld+jwt') {
        revoked = await checkRevocationStatus(
          transmute.text.decoder.decode(vcContent)
        );
        console.log(`Revocation Check: ${revoked ? "Revoked" : "Not Revoked"}`);
      }

      // Store results
      const credentialValid = vcValidation.verified && !revoked;
      allCredentialsValid = allCredentialsValid && credentialValid;

      credentialResults.push({
        index,
        valid: credentialValid,
        credential: vc,
        validationResult: vcValidation,
        revoked
      });
      for (const [i, credential] of vpResult.content.verifiableCredential.entries()) {
        console.log(`Credential ${i}:`, credential);
      }
    }
  }
    return {
    verified: allCredentialsValid ,
    vpValidation: vpResult,
    credentialResults,
    errors: [
      ...credentialResults.filter(c => !c.valid).map(c => ({
        credentialIndex: c.index,
        error: c.revoked ? 'Revoked credential' : 'Invalid credential',
        details: c.validationResult
      })),
      
    ]
  };
}

