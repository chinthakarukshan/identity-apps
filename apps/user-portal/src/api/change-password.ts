/**
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { AuthenticateSessionUtil, AuthenticateUserKeys } from "@wso2is/authentication";
import { AxiosHttpClient } from "@wso2is/http";
import { ServiceResourcesEndpoint } from "../configs";
import { HttpMethods } from "../models";

/**
 * Get an axios instance.
 *
 * @type {AxiosHttpClientInstance}
 */
const httpClient = AxiosHttpClient.getInstance();

/**
 * Updates the user's password.
 *
 * @param {string} newPassword newly assigned password.
 * @return {Promise<any>} a promise containing the response.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
const updateToNewPassword = (newPassword: string): Promise<any> => {

    const requestConfig = {
        data: {
            Operations: [
                {
                    op: "add",
                    value: {
                        password: newPassword
                    }
                }
            ],
            schemas: [ "urn:ietf:params:scim:api:messages:2.0:PatchOp" ]
        },
        headers: {
            "Content-Type": "application/json"
        },
        method: HttpMethods.PATCH,
        url: ServiceResourcesEndpoint.me
    };

    return httpClient.request(requestConfig)
        .then((response) => {
            if (response.status !== 200) {
                return Promise.reject("Failed to update password.");
            }
            return Promise.resolve(response);
        })
        .catch((error) => {
            return Promise.reject(error);
        });
};


/**
 * Updates the user's password.
 *
 * @param {string} currentPassword currently registered password.
 * @return {Promise<any>} a promise containing the response.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
const validateCurrentPassword = (currentPassword: string): Promise<any> => {
    // We're currently using the authentication endpoint to validate the current password. If the password is
    // different, the server responds with a status code `401`. The callbacks handle 401 errors and
    // terminates the session. To bypass the callbacks disable the handler when the client is initialized.
    // TODO: Remove this function once the API supports current password validation.
    httpClient.disableHandler();

    const requestConfig = {
        auth: {
            password: currentPassword,
            username: AuthenticateSessionUtil.getSessionParameter(AuthenticateUserKeys.USERNAME)
        },
        headers: {
            "Content-Type": "application/json"
        },
        data: {},
        method: HttpMethods.POST,
        url: ServiceResourcesEndpoint.authentication
    };

    return httpClient.request(requestConfig)
        .then((response) => {
            if (response.status !== 200) {
                return Promise.reject("Failed to update password.");
            }
            return Promise.resolve(response);
        })
        .catch((error) => {
            return Promise.reject(error);
        })
        .finally(() => {
            httpClient.enableHandler();
        });
};

/**
 * Updates the user's password.
 *
 * @param {string} currentPassword currently registered password.
 * @param {string} newPassword newly assigned password.
 * @return {Promise<any>} a promise containing the response.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
export const updatePassword = (currentPassword: string, newPassword: string): Promise<any> => {

    // Validate the current password.
    return validateCurrentPassword(currentPassword)
        .then((response) => {
            if (response.status !== 200) {
                return Promise.reject("Failed to update password.");
            }
            // Update the password to the new value.
            return updateToNewPassword(newPassword);
        })
        .catch((error) => {
            return Promise.reject(error);
        })
};
