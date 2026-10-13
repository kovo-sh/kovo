import { API_ENDPOINT_LIST } from "./api/registry.js";

export * from "./api-key-authority-schemas.js";

const managementPermissions = new Map(
  API_ENDPOINT_LIST.map((endpoint) => [
    endpoint.operationId,
    endpoint.authorization.managementPermission,
  ]),
);

/** Management aliases come only from registered endpoint descriptors. Unknown operations stay exact. */
export function managementPermissionOperation(operation: string): string {
  return managementPermissions.get(operation) ?? operation;
}
