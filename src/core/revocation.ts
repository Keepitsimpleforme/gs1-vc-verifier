import { splitJwt } from "./input";
import { inputJWT } from "../test/test";
import * as transmute from '@transmute/verifiable-credentials';
import { StatusList } from '../utils/statusList/StatusList';

export async function checkRevocationStatus(vc: any): Promise<boolean> {
  const decodedJWT = splitJwt(vc);
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

        return isRevoked;
      } catch (error) {
        console.error('Error checking revocation status:', error);
        return false;
      }
    }
  }
  return false;
}

// Execute the function
checkRevocationStatus(inputJWT).then(console.log).catch(console.error);