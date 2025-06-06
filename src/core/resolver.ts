// resolver.ts
import { Resolver } from "did-resolver";
import { getResolver } from "web-did-resolver";
import * as transmute from '@transmute/verifiable-credentials';
import { PublicKeyWithContentType } from "@transmute/verifiable-credentials";
import { splitJwt } from './input';

interface ResolverRequest {
  id?: string;
  type: string;
  content?: Uint8Array;
  purpose?: string;
}

export const resolver = {
  resolve: async (req: ResolverRequest): Promise<PublicKeyWithContentType> => {
    const { id, type, content } = req;

    if (type === "application/vc-ld+jwt" && content) {
      const jwt = transmute.text.decoder.decode(content);
      const { header } = splitJwt(jwt);
      const kid = header.kid;
      const did = kid.split("#")[0];

      const webResolver = getResolver();
      const resolver = new Resolver({ ...webResolver });
      const didDocument = await resolver.resolve(did);

      const verificationMethod = didDocument.didDocument?.verificationMethod?.find(
        (vm) => vm.id === kid
      );

      if (!verificationMethod?.publicKeyJwk) {
        throw new Error(`No matching verification method found for kid: ${kid}`);
      }

      return {
        type: "application/jwk+json",
        content: new TextEncoder().encode(JSON.stringify(verificationMethod.publicKeyJwk))
      };
    }

    throw new Error("Unsupported type or missing parameters");
  }
};

// Separate resolver for schema and status checks
export const resourceResolver = {
  resolve: async (req: ResolverRequest) => {
    const { id, type } = req;

    if (type === "application/schema+json" && id) {
      const schemaResponse = await fetch(id);
      const schema = await schemaResponse.json();
      return {
        type: "application/schema+json",
        content: new TextEncoder().encode(JSON.stringify(schema))
      };
    }

    if (type === "application/vc-ld+jwt" && id) {
      const statusListResponse = await fetch(id);
      const statusListJwt = await statusListResponse.text();
      return {
        type: "application/vc-ld+jwt",
        content: new TextEncoder().encode(statusListJwt)
      };
    }

    throw new Error("Unsupported type or missing parameters");
  }
};
