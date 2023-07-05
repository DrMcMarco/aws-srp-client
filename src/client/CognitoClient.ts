import axios from 'axios';
import { AmzTarget, ChangePasswordParams, ChangePasswordResponse, PasswordVerifierResult } from './Types';

export class CognitoClient {
  Region: string;
  ClientId: string;

  constructor(region: string, clientId: string) {
    this.Region = region;
    this.ClientId = clientId;
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
    const cognitoUrl = `https://cognito-idp.${this.Region}.amazonaws.com`;

    const params: ChangePasswordParams = {
      AccessToken: accessToken,
      PreviousPassword: previousPassword,
      ProposedPassword: newPassword,
    };

    const response = await axios.request({
      url: cognitoUrl,
      method: 'POST',
      headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': AmzTarget.ChangePassword },
      data: JSON.stringify(params),
    });

    return {
      StatusCode: response.status,
      Error: JSON.stringify(response.data),
    };
  }

  /**
   * Build a Cognito Auth Domain with your chosen prefix and region.
   * @param prefix Chosen URL prefix
   * @returns Your Cognito Auth Domain
   */
  CognitoDomain(prefix: string) {
    return `https://${prefix}.auth.${this.Region}.amazoncognito.com`;
  }

  /**
   * Exchange a refresh token for new access and id tokens
   * @param domain Cognito Auth Domain
   * @param refreshToken Valid Refresh Token
   * @returns Object with new Access-/Id Tokens, object with error message otherwise
   */
  async GetAccessFromRefreshToken(domain: string, refreshToken: string): Promise<PasswordVerifierResult> {
    try {
      const response = await axios.request({
        url: `${domain}/oauth2/token`,
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        data: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: this.ClientId,
          refresh_token: refreshToken,
        }).toString(),
      });

      return {
        Success: true,
        NewPasswordRequired: false,
        AuthenticationResult: {
          AccessToken: response.data.access_token,
          IdToken: response.data.id_token,
          RefreshToken: refreshToken,
          ExpiresIn: response.data.expires_in,
          TokenType: response.data.token_type,
        },
      };
    } catch (err) {
      return {
        Success: false,
        NewPasswordRequired: false,
        Error: err,
      };
    }
  }
}
