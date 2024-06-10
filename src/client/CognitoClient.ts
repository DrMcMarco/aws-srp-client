import axios from 'axios';
import { AmzTarget, ChangePasswordParams, ChangePasswordResponse, ConfirmForgotPasswordParams, ConfirmForgotPasswordResponse, ForgotPasswordParams, ForgotPasswordResponse, PasswordVerifierResult } from './Types';

export class CognitoClient {
  Region: string;
  ClientId: string;
  CognitoUrl: string;

  constructor(region: string, clientId: string) {
    this.Region = region;
    this.ClientId = clientId;
    this.CognitoUrl = `https://cognito-idp.${this.Region}.amazonaws.com`;
  }

  /**
   * Change a users password.
   * @param accessToken Valid access token for the user whos password you want to change
   * @param previousPassword Current password
   * @param newPassword New password
   * @returns Object with StatusCode 200 if it worked, StatusCode != 200 and Error message otherwise
   */
  async ChangePassword(
    accessToken: string,
    previousPassword: string,
    newPassword: string,
  ): Promise<ChangePasswordResponse> {
    const params: ChangePasswordParams = {
      AccessToken: accessToken,
      PreviousPassword: previousPassword,
      ProposedPassword: newPassword,
    };

    const response = await axios.request({
      url: this.CognitoUrl,
      method: 'POST',
      headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': AmzTarget.ChangePassword },
      data: JSON.stringify(params),
    });

    return {
      StatusCode: response.status,
      Error: JSON.stringify(response.data),
    };
  }

  async ForgotPassword(
    username: string
  ): Promise<ForgotPasswordResponse> {
    const params: ForgotPasswordParams = {
      ClientId: this.ClientId,
      Username: username
    }

    const response = await axios.request({
      url: this.CognitoUrl,
      method: 'POST',
      headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': AmzTarget.ForgotPassword },
      data: JSON.stringify(params)
    });

    return {
      CodeDeliveryDetails: response.data.CodeDeliveryDetails ? response.data.CodeDeliveryDetails : {},
      Error: !response.data.CodeDeliveryDetails ? response.data : {}
    }
  }

  async ConfirmForgotPassword(
    username: string,
    code: string,
    newPassword: string
  ): Promise<ConfirmForgotPasswordResponse> {
    const params: ConfirmForgotPasswordParams = {
      ClientId: this.ClientId,
      ConfirmationCode: code,
      Username: username,
      Password: newPassword
    }

    const response = await axios.request({
      url: this.CognitoUrl,
      method: 'POST',
      headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': AmzTarget.ConfirmForgotPassword },
      data: JSON.stringify(params)
    });

    return {
      Success: response.status === 200,
      Error: JSON.stringify(response.data)
    }
  }

  /**
   * Build a Cognito Auth Domain with your chosen prefix and region.
   * @deprecated Not needed anymore, will be removed in the next version.
   * @param prefix Chosen URL prefix
   * @returns Your Cognito Auth Domain
   */
  CognitoDomain(prefix: string) {
    return `https://${prefix}.auth.${this.Region}.amazoncognito.com`;
  }
}
