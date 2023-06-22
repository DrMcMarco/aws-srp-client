type AuthParams = {
  USERNAME: string;
  SRP_A: string;
};

type AuthRequest = {
  AuthParameters: AuthParams;
  AuthFlow: string;
  ClientId: string;
};

type PasswordVerifierChallengeParams = {
  SALT: string;
  SECRET_BLOCK: string;
  USER_ID_FOR_SRP: string;
  USERNAME: string;
  SRP_B: string;
};

type AuthResponse = {
  ChallengeName: string;
  ChallengeParameters: PasswordVerifierChallengeParams;
};

type ChallengeResponse = {
  TIMESTAMP: string;
  USERNAME: string;
  PASSWORD_CLAIM_SECRET_BLOCK: string;
  PASSWORD_CLAIM_SIGNATURE: string;
};

type ChallengeRequest = {
  ClientId: string;
  ChallengeName: string;
  ChallengeResponses: ChallengeResponse;
};

type AuthResult = {
  Success: boolean;
  AuthenticationResult?: {
    AccessToken: string;
    IdToken: string;
    RefreshToken: string;
    ExpiresIn: number;
    TokenType: string;
  };
  ChallengeParameters?: any;
  Error?: any;
};

export {
  AuthParams,
  AuthRequest,
  PasswordVerifierChallengeParams,
  AuthResponse,
  ChallengeRequest,
  ChallengeResponse,
  AuthResult,
};
