// resolver.ts (final)
import { Resolver } from "did-resolver";
import { getResolver } from "web-did-resolver";
import * as transmute from '@transmute/verifiable-credentials';
import { PublicKeyWithContentType, SupportedKeyFormats } from "@transmute/verifiable-credentials";
import { splitJwt } from './input';
import { getDidDocumentWithCache, getDidDocumentDirect } from '../cache/cache';

interface ResolverRequest {
  id?: string;
  type: string;
  content?: Uint8Array;
  purpose?: string;
}

interface ResolverResponse {
  type: string;
  content: Uint8Array;
}

export function createResolver(fetchDidDocument: (did: string) => Promise<any>) {
  return {
    resolve: async (req: ResolverRequest): Promise<ResolverResponse> => {
      const { id, type, content } = req;

      // Handle VP JWT signature verification
      if ((type === "application/vp-ld+jwt" || type === "application/vc-ld+jwt") && content) {
        const jwt = transmute.text.decoder.decode(content);
        const { header } = splitJwt(jwt);
        const kid = header.kid;
        const did = kid.split("#")[0];

        const didDocument = await fetchDidDocument(did);

        const verificationMethod = didDocument.didDocument?.verificationMethod?.find(
          (vm: any) => vm.id === kid
        );

        if (!verificationMethod?.publicKeyJwk) {
          throw new Error(`No matching verification method found for kid: ${kid}`);
        }

        return {
          type: "application/jwk+json",
          content: new TextEncoder().encode(JSON.stringify(verificationMethod.publicKeyJwk))
        };
      }

      // Handle direct JWK requests (e.g., from VC verification)
      if (type === "application/jwk+json" && id) {
        const did = id.split("#")[0];
        const didDocument = await fetchDidDocument(did);

        const verificationMethod = didDocument.didDocument?.verificationMethod?.find(
          (vm: any) => vm.id === id
        );

        if (!verificationMethod?.publicKeyJwk) {
          throw new Error(`No matching verification method found for id: ${id}`);
        }

        return {
          type: "application/jwk+json",
          content: new TextEncoder().encode(JSON.stringify(verificationMethod.publicKeyJwk))
        };
      }

      // Handle schema validation
      if (type === "application/schema+json" && id) {
        const schemaResponse = await fetch(id);
        const schema = await schemaResponse.json();
        return {
          type: "application/schema+json",
          content: new TextEncoder().encode(JSON.stringify(schema))
        };
      }

      // Handle status list checks
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
}

export const resolverWithCache = createResolver(getDidDocumentWithCache);
export const resolverNoCache = createResolver(getDidDocumentDirect);
