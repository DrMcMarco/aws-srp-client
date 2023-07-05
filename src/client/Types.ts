enum AmzTarget {
  InitiateAuth = 'AWSCognitoIdentityProviderService.InitiateAuth',
  AuthChallenge = 'AWSCognitoIdentityProviderService.RespondToAuthChallenge',
  ChangePassword = 'AWSCognitoIdentityProviderService.ChangePassword'
}

interface InitiateAuthParams {
  USERNAME: string;
  SRP_A: string;
}

interface InitiateAuthRequest {
  AuthParameters: InitiateAuthParams;
  AuthFlow: string;
  ClientId: string;
}

interface PasswordVerifierChallengeParams {
  SALT: string;
  SECRET_BLOCK: string;
  USER_ID_FOR_SRP: string;
  USERNAME: string;
  SRP_B: string;
}

interface InitiateAuthResponse {
  ChallengeName: string;
  ChallengeParameters: PasswordVerifierChallengeParams;
}

interface ChallengeResponse {
  USERNAME: string;
}

interface PasswordVerifierChallengeResponse extends ChallengeResponse {
  TIMESTAMP?: string;
  PASSWORD_CLAIM_SECRET_BLOCK?: string;
  PASSWORD_CLAIM_SIGNATURE?: string;
}

interface NewPasswordChallengeReponse extends ChallengeResponse {
  NEW_PASSWORD: string;
  SECRET_HASH?: string;
}

interface RespondToAuthChallengeRequest {
  ClientId: string;
  ChallengeName: string;
  ChallengeResponses: ChallengeResponse;
  Session?: string;
}

interface PasswordVerifierResult {
  Success: boolean;
  NewPasswordRequired: boolean;
  Session?: string;
  AuthenticationResult?: {
    AccessToken: string;
    IdToken: string;
    RefreshToken: string;
    ExpiresIn: number;
    TokenType: string;
  };
  ChallengeParameters?: any;
  Error?: any;
}

interface ChangePasswordParams {
  AccessToken: string;
  PreviousPassword: string;
  ProposedPassword: string;
}

interface ChangePasswordResponse {
  StatusCode: number;
  Error?: string;
}

export {
  AmzTarget,
  InitiateAuthParams,
  InitiateAuthRequest,
  PasswordVerifierChallengeParams,
  InitiateAuthResponse,
  RespondToAuthChallengeRequest,
  ChallengeResponse,
  PasswordVerifierResult,
  PasswordVerifierChallengeResponse,
  NewPasswordChallengeReponse,
  ChangePasswordParams,
  ChangePasswordResponse
};
