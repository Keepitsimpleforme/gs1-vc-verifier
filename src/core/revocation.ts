import { splitJwt } from "./input";
import { inputJWT } from "../test/test";
import * as transmute from '@transmute/verifiable-credentials';
import { StatusList } from '../utils/statusList/StatusList';

export async function checkRevocationStatus() {
  const decodedJWT = splitJwt(inputJWT);
  const payload = decodedJWT.payload;

  // Check if credential has status information
  if (payload.credentialStatus) {
    const status = payload.credentialStatus;
    console.log('Credential status:', status);
    
    if (status.type === 'BitstringStatusListEntry' && status.statusPurpose === 'revocation') {
      try {
        // Fetch the status list credential
        const statusListJWT = await fetch(status.statusListCredential).then(res => res.text());
        
        // Decode the JWT to get the status list credential
        const statusListCredential = splitJwt(statusListJWT).payload;
        
        // Check the status using our StatusList implementation
        const isRevoked = await StatusList.checkStatus({
          claimset: statusListCredential,
          purpose: 'revocation',
          position: parseInt(status.statusListIndex),
        });

        if (isRevoked) {
          console.log('Credential is revoked');
        } else {
          console.log('Credential is valid');
        }
      } catch (error) {
        console.error('Error checking revocation status:', error);
      }
    }
  } else {
    console.log('Credential has no status information');
  }
}

// Execute the function
checkRevocationStatus().catch(console.error);