enum AmzTarget {
  InitiateAuth = 'AWSCognitoIdentityProviderService.InitiateAuth',
  AuthChallenge = 'AWSCognitoIdentityProviderService.RespondToAuthChallenge',
  ChangePassword = 'AWSCognitoIdentityProviderService.ChangePassword',
  ForgotPassword = 'AWSCognitoIdentityProviderService.ForgotPassword',
  ConfirmForgotPassword = 'AWSCognitoIdentityProviderService.ConfirmForgotPassword',
}

enum AuthFlow {
  UserSrpAuth = 'USER_SRP_AUTH',
  RefreshTokenAuth = 'REFRESH_TOKEN',
}

interface InitiateAuthParams {
  USERNAME: string;
  SRP_A: string;
}

interface RefreshTokenParams {
  REFRESH_TOKEN: string;
  SECRET_HASH?: string;
}

interface InitiateAuthRequest {
  AuthParameters: InitiateAuthParams | RefreshTokenParams;
  AuthFlow: AuthFlow;
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

interface ForgotPasswordParams {
  ClientId: string;
  SecretHash?: string;
  Username: string;
  ClientMetadata?: Record<string, string>
}

interface ForgotPasswordResponse {
  CodeDeliveryDetails?: {
    AttributeName: string;
    DeliveryMedium: string;
    Destination: string;
  };
  Error?: {
    __type: string;
    message: string;
  };
}

interface ConfirmForgotPasswordParams {
  ClientId: string;
  SecretHash?: string;
  Username: string;
  ConfirmationCode: string;
  Password: string;
}

interface ConfirmForgotPasswordResponse {
  Success: boolean;
  Error?: any;
}

export {
  AmzTarget,
  AuthFlow,
  InitiateAuthParams,
  RefreshTokenParams,
  InitiateAuthRequest,
  PasswordVerifierChallengeParams,
  InitiateAuthResponse,
  RespondToAuthChallengeRequest,
  ChallengeResponse,
  PasswordVerifierResult,
  PasswordVerifierChallengeResponse,
  NewPasswordChallengeReponse,
  ChangePasswordParams,
  ChangePasswordResponse,
  ForgotPasswordParams,
  ForgotPasswordResponse,
  ConfirmForgotPasswordParams,
  ConfirmForgotPasswordResponse,
};
