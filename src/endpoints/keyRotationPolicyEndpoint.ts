// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { ServiceResult } from "../utils/ServiceResult";
import { enableEndpoint } from "../utils/Tooling";
import { keyRotationPolicyMap } from "../repositories/Maps";
import { KeyRotationPolicy } from "../policies/KeyRotationPolicy";
import { IKeyRotationPolicy } from "../policies/IKeyRotationPolicy";
import { LogContext } from "../utils/Logger";

// Enable the endpoint
enableEndpoint();

/**
 * Retrieves the key rotation policy.
 * @returns A ServiceResult containing the key rotation policy properties.
 */
export const keyRotationPolicy = (
  request: ccfapp.Request<void>,
): ServiceResult<string | IKeyRotationPolicy> => {
  const logContext = new LogContext().appendScope("keyRotationPolicyEndpoint");

  try {
    const result =
      KeyRotationPolicy.getKeyRotationPolicyFromMap(keyRotationPolicyMap, logContext);
    if (result === undefined) {
      return ServiceResult.Failed<string>(
        { errorMessage: "No key rotation policy configured" },
        404,
        logContext
      );
    }
    return ServiceResult.Succeeded<IKeyRotationPolicy>(result, logContext);
  } catch (error: any) {
    return ServiceResult.Failed<string>({ errorMessage: error.message }, 500, logContext);
  }
};
