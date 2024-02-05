import { HashUtils } from '../utils/HashUtils';
import {
  AmzTarget,
  InitiateAuthParams,
  PasswordVerifierChallengeParams,
  RespondToAuthChallengeRequest,
  InitiateAuthRequest,
  PasswordVerifierResult,
  InitiateAuthResponse,
  PasswordVerifierChallengeResponse,
  NewPasswordChallengeReponse,
  RefreshTokenParams,
  AuthFlow,
} from './Types';
import CryptoJS from 'crypto-js';
import bigInt, { BigInteger } from 'big-integer';
import moment from 'moment';
import axios from 'axios';

export class AwsSrpClient {
  private static N_HEX: string =
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' +
    'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
    'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' +
    'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' +
    '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';
  private static G_HEX: string = '2';

  Region: string;
  PoolId: string;
  ClientId: string;
  BigN: BigInteger;
  G: BigInteger;
  K: BigInteger;
  SmallAValue: BigInteger;
  LargeAValue: BigInteger;

  constructor(region: string, poolId: string, clientId: string) {
    this.Region = region;
    this.PoolId = poolId;
    this.ClientId = clientId;
    this.BigN = HashUtils.HexToLong(AwsSrpClient.N_HEX);
    this.G = HashUtils.HexToLong(AwsSrpClient.G_HEX);
    this.K = HashUtils.HexToLong(HashUtils.HexHash('00' + AwsSrpClient.N_HEX + '0' + AwsSrpClient.G_HEX));
    this.SmallAValue = bigInt(0);
    this.LargeAValue = bigInt(0);
  }

  public Initialize() {
    this.SmallAValue = this.GenerateRandomSmallA();
    this.LargeAValue = this.CalculateA();
  }

  private GenerateRandomSmallA(): BigInteger {
    const random = HashUtils.GetRandom(128);
    return random.mod(this.BigN);
  }

  private CalculateA(): BigInteger {
    const bigA = this.G.modPow(this.SmallAValue, this.BigN);
    if (bigA === this.BigN) throw new Error('Safety check for A failed.');
    return bigA;
  }

  /**
   *
   * @returns The generated SRP_A value for an InitiateAuth request.
   */
  public GetSrpA(): string {
    return HashUtils.LongToHex(this.LargeAValue);
  }

  private GetPasswordAuthenticationKey(username: string, password: string, serverBValue: BigInteger, salt: string) {
    const uValue: BigInteger = HashUtils.CalculateU(this.LargeAValue, serverBValue);
    if (uValue === bigInt()) throw new Error('U cannot be zero.');
    const usernamePassword = `${this.PoolId.split('_')[1]}${username}:${password}`;
    const usernamePasswordHash = HashUtils.HashSha256(CryptoJS.enc.Utf8.parse(usernamePassword));

    const xValue: BigInteger = HashUtils.HexToLong(HashUtils.HexHash(HashUtils.PadHex(salt) + usernamePasswordHash));
    const gModPowXn: BigInteger = this.G.modPow(xValue, this.BigN);
    const intValue2: BigInteger = serverBValue.minus(this.K.times(gModPowXn));
    let sValue: BigInteger = intValue2.modPow(this.SmallAValue.plus(uValue.times(xValue)), this.BigN);
    if (sValue < bigInt()) sValue = sValue.plus(this.BigN);
    return HashUtils.ComputeHdkf(
      CryptoJS.enc.Hex.parse(HashUtils.PadHex(sValue)),
      CryptoJS.enc.Hex.parse(HashUtils.PadHex(HashUtils.LongToHex(uValue))),
    );
  }

  /**
   * Generate a response for an AuthChallenge.
   * @param password The user password
   * @param challengeParams The response from an InitiateAuth request
   * @returns A Password Verifier challenge response
   */
  public ProcessChallenge(
    password: string,
    challengeParams: PasswordVerifierChallengeParams,
  ): PasswordVerifierChallengeResponse {
    const timestamp = moment.utc().format('ddd MMM D HH:mm:ss UTC yyyy');
    const hkdf = this.GetPasswordAuthenticationKey(
      challengeParams.USER_ID_FOR_SRP,
      password,
      HashUtils.HexToLong(challengeParams.SRP_B),
      challengeParams.SALT,
    );
    const secretBlockBytes = CryptoJS.enc.Base64.parse(challengeParams.SECRET_BLOCK);
    const poolIdBytes = CryptoJS.enc.Utf8.parse(this.PoolId.split('_')[1]);
    const userIdBytes = CryptoJS.enc.Utf8.parse(challengeParams.USER_ID_FOR_SRP);
    const timestampBytes = CryptoJS.enc.Utf8.parse(timestamp);

    const msg = poolIdBytes.concat(userIdBytes).concat(secretBlockBytes).concat(timestampBytes);
    const hmac = CryptoJS.HmacSHA256(msg, hkdf);
    const signature = CryptoJS.enc.Base64.stringify(hmac);

    return {
      USERNAME: challengeParams.USER_ID_FOR_SRP,
      TIMESTAMP: timestamp,
      PASSWORD_CLAIM_SECRET_BLOCK: challengeParams.SECRET_BLOCK,
      PASSWORD_CLAIM_SIGNATURE: signature,
    };
  }

  /**
   * Authenticate a user via their password.
   *
   * This method also re-initializes the SmallA and LargeA values.
   *
   * @param username Cognito Username
   * @param password Cognito Password
   * @returns An object with Id-/Access-/Refresh tokens on success, an error object on failure
   */
  public async AuthenticateUser(username: string, password: string): Promise<PasswordVerifierResult | undefined> {
    try {
      this.Initialize();

      const cognitoUrl = `https://cognito-idp.${this.Region}.amazonaws.com`;

      const authParams: InitiateAuthParams = {
        USERNAME: username,
        SRP_A: this.GetSrpA(),
      };

      const authRequest: InitiateAuthRequest = {
        AuthFlow: AuthFlow.UserSrpAuth,
        ClientId: this.ClientId,
        AuthParameters: authParams,
      };

      const initAuthResponse = await axios.request({
        url: cognitoUrl,
        method: 'POST',
        headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': AmzTarget.InitiateAuth },
        data: JSON.stringify(authRequest),
      });

      if (initAuthResponse) {
        const initAuthBody: InitiateAuthResponse = initAuthResponse.data;

        if (initAuthBody && initAuthBody.ChallengeName && initAuthBody.ChallengeName === 'PASSWORD_VERIFIER') {
          const challengeResponse: PasswordVerifierChallengeResponse = this.ProcessChallenge(
            password,
            initAuthBody.ChallengeParameters,
          );
          const challengeRequest: RespondToAuthChallengeRequest = {
            ChallengeName: initAuthBody.ChallengeName,
            ChallengeResponses: challengeResponse,
            ClientId: this.ClientId,
          };

          const authChallengeResponse = await axios.request({
            url: cognitoUrl,
            method: 'POST',
            headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': AmzTarget.AuthChallenge },
            data: JSON.stringify(challengeRequest),
          });

          if (authChallengeResponse) {
            const verifierResult: PasswordVerifierResult = {
              Success: false,
              NewPasswordRequired: false,
            };

            if (authChallengeResponse.data.AuthenticationResult) {
              verifierResult.Success = true;
              verifierResult.AuthenticationResult = authChallengeResponse.data.AuthenticationResult;
              verifierResult.ChallengeParameters = authChallengeResponse.data.ChallengeParameters;
            } else if (
              authChallengeResponse.data.ChallengeName &&
              authChallengeResponse.data.ChallengeName === 'NEW_PASSWORD_REQUIRED'
            ) {
              verifierResult.Success = true;
              verifierResult.NewPasswordRequired = true;
              verifierResult.Session = authChallengeResponse.data.Session;
            }

            return verifierResult;
          }
        }
      }
    } catch (err) {
      return {
        Success: false,
        NewPasswordRequired: false,
        Error: err,
      };
    }
  }

  /**
   * Authenticate a user via a refresh token.
   *
   * This method generates new Id-/Access-Token.
   *
   * @param refreshToken A valid refresh token
   * @returns An object with Id-/Access-/Refresh tokens on success, an error object on failure
   */
  public async AuthenticateUserWithRefreshToken(refreshToken: string): Promise<PasswordVerifierResult | undefined> {
    try {
      const cognitoUrl = `https://cognito-idp.${this.Region}.amazonaws.com`;

      const authParams: RefreshTokenParams = {
        REFRESH_TOKEN: refreshToken,
      };

      const authRequest: InitiateAuthRequest = {
        AuthFlow: AuthFlow.RefreshTokenAuth,
        ClientId: this.ClientId,
        AuthParameters: authParams,
      };

      const initAuthResponse = await axios.request({
        url: cognitoUrl,
        method: 'POST',
        headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': AmzTarget.InitiateAuth },
        data: JSON.stringify(authRequest),
      });

      if (initAuthResponse) {
        const verifierResult: PasswordVerifierResult = {
          Success: false,
          NewPasswordRequired: false,
        };

        if (initAuthResponse.data.AuthenticationResult) {
          verifierResult.Success = true;
          verifierResult.AuthenticationResult = initAuthResponse.data.AuthenticationResult;
          verifierResult.ChallengeParameters = initAuthResponse.data.ChallengeParameters;
        } else if (
          initAuthResponse.data.ChallengeName &&
          initAuthResponse.data.ChallengeName === 'NEW_PASSWORD_REQUIRED'
        ) {
          verifierResult.Success = true;
          verifierResult.NewPasswordRequired = true;
          verifierResult.Session = initAuthResponse.data.Session;
        }

        return verifierResult;
      }
    } catch (err) {
      return {
        Success: false,
        NewPasswordRequired: false,
        Error: err,
      };
    }
  }

  public async SetNewPassword(
    session: string,
    username: string,
    newPassword: string,
  ): Promise<PasswordVerifierResult | undefined> {
    const cognitoUrl = `https://cognito-idp.${this.Region}.amazonaws.com`;

    const newPasswordChallengeResponse: NewPasswordChallengeReponse = {
      USERNAME: username,
      NEW_PASSWORD: newPassword,
    };

    const newPasswordChallengeRequest: RespondToAuthChallengeRequest = {
      ChallengeName: 'NEW_PASSWORD_REQUIRED',
      ClientId: this.ClientId,
      Session: session,
      ChallengeResponses: newPasswordChallengeResponse,
    };

    try {
      const newPasswordResponse = await axios.request({
        url: cognitoUrl,
        method: 'POST',
        headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': AmzTarget.AuthChallenge },
        data: JSON.stringify(newPasswordChallengeRequest),
      });

      if (newPasswordResponse) {
        return {
          Success: true,
          NewPasswordRequired: false,
          AuthenticationResult: newPasswordResponse.data.AuthenticationResult,
          ChallengeParameters: newPasswordResponse.data.ChallengeParameters,
        };
      }
    } catch (err) {
      return {
        Success: false,
        NewPasswordRequired: false,
        Error: err,
      };
    }
  }
}
