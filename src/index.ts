import { AwsSrpClient } from './client/AwsSrpClient';
import { HashUtils } from './utils/HashUtils';
import {
  AuthParams,
  AuthRequest,
  AuthResponse,
  ChallengeRequest,
  ChallengeResponse,
  PasswordVerifierChallengeParams,
  AuthResult,
} from './client/Types';

export {
  AwsSrpClient,
  HashUtils,
  AuthParams,
  AuthRequest,
  AuthResponse,
  ChallengeRequest,
  ChallengeResponse,
  PasswordVerifierChallengeParams,
  AuthResult,
};

// const client = new AwsSrpClient('region', 'pool-id', 'client-id');
// client.AuthenticateUser('user', 'password');

// const response: AuthResponse = {
//     ChallengeName: "PASSWORD_VERIFIER",
//     ChallengeParameters: {
//         SALT: "aqsfyf326546sdgsdfasda65s1d6a",
//         SECRET_BLOCK: "jdhgsjsdghkjklyvda65sf1w64h615l651c6a5sd41fg65g4j1651c651hb651d6516kj16l414vca32c32x2g6r4n61yc651hnj84rz9k451acy1g984w6v21y1b9641h16dxb4rj9n61C1Y65G4X9684B1JM94B65s21v4ds6fhg==",
//         USER_ID_FOR_SRP: "user",
//         USERNAME: "user",
//         SRP_B: "laskdjfglsdjgietu099sd8h49dsgd4s9dgf4s9dg4s5g4sdg4s94af4aFHd9318u6ßsdfoi120hfv28094ghß2jfldxmg20894ujtßmmhß9j2gimcgklkgüpdskt902fölksdöfk390utßskdfl,k1ß3ujsdjkf"
//     }
// };

// client.Initialize();
// const challengeParams = client.ProcessChallenge("password", response.ChallengeParameters);

// console.log(JSON.stringify(challengeParams));
