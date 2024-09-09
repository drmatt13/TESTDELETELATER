"use client";

import { useState, FormEvent } from "react";

import {
  CognitoUser,
  CognitoUserSession,
  CognitoUserPool,
  CognitoUserAttribute,
  AuthenticationDetails,
} from "amazon-cognito-identity-js";

interface CognitoSignUpError {
  message: string;
  code:
    | "UsernameExistsException"
    | "InvalidPasswordException"
    | "InvalidParameterException"
    | "CodeDeliveryFailureException"
    | "UserLambdaValidationException"
    | "NotAuthorizedException"
    | "TooManyRequestsException"
    | "InternalErrorException";
  name: string;
  stack?: string; // Optional stack trace
}

interface CognitoSignInError {
  message: string;
  code:
    | "NotAuthorizedException"
    | "UserNotFoundException"
    | "PasswordResetRequiredException"
    | "UserNotConfirmedException"
    | "MFAMethodNotFoundException"
    | "InvalidParameterException"
    | "TooManyFailedAttemptsException"
    | "TooManyRequestsException"
    | "InternalErrorException"; // In case of AWS Cognito internal error
  name: string;
  stack?: string; // Optional stack trace
}

// create a new CognitoUserPool instance
const userPool = new CognitoUserPool({
  UserPoolId: process.env.NEXT_PUBLIC_COGNITO_USER_POOL_ID as string,
  ClientId: process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID as string,
});

export default function Home() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [password, setPassword] = useState("");
  const [formState, setFormState] = useState<"register" | "login">("login");

  const register = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);

    // Create a new CognitoUserAttribute instance
    const attributeList = [
      new CognitoUserAttribute({
        Name: "email",
        Value: email,
      }),
    ];

    // Call the signUp method on the userPool instance
    userPool.signUp(email, password, attributeList, [], (error, result) => {
      if (error || !result) {
        console.error("Error:", (error as CognitoSignUpError).code);
        setLoading(false);
        return;
      }

      // Get the cognitoUser from the result
      const cognitoUser = result.user;

      console.log("User created for: " + cognitoUser.getUsername());
      setLoading(false);
    });
  };

  const login = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);

    // Create a new CognitoUser instance
    const userData = {
      Username: email,
      Pool: userPool,
    };

    const cognitoUser = new CognitoUser(userData);

    // Create a new AuthenticationDetails instance
    const authenticationDetails = new AuthenticationDetails({
      Username: email,
      Password: password,
    });

    // use the authenticationDetails instance as an argument to the authenticateUser method on the cognitoUser instance to authenticate the user
    cognitoUser.authenticateUser(authenticationDetails, {
      onSuccess: (session: CognitoUserSession) => {
        // used to authorize requests to APIs
        console.log("access token: " + session.getAccessToken().getJwtToken());
        // Access Token
        // {
        //   "sub": "user-unique-id",               // Unique identifier for the user (subject)
        //   "iss": "https://cognito-idp.<region>.amazonaws.com/<user-pool-id>", // Issuer URL (Cognito User Pool)
        //   "client_id": "client-id",              // Client ID of the application
        //   "origin_jti": "original-jwt-id",       // Original JWT ID for tracking
        //   "event_id": "event-id",                // Unique event ID
        //   "token_use": "access",                 // Token type (access token)
        //   "scope": "aws.cognito.signin.user.admin", // Scopes granted to the token
        //   "auth_time": 1234567890,               // Time the user was authenticated (Unix timestamp)
        //   "exp": 1234569990,                     // Expiration time (Unix timestamp)
        //   "iat": 1234567890,                     // Issued at time (Unix timestamp)
        //   "jti": "jwt-id",                       // Unique identifier for this token (JWT ID)
        //   "username": "user@example.com"          // Username or email of the user
        // }

        // contains information about the user session
        console.log("id token: " + session.getIdToken().getJwtToken());
        // ID Token
        // {
        //   "sub": "user-unique-id",               // Unique identifier for the user (subject)
        //   "email_verified": true,                // Whether the user's email is verified
        //   "iss": "https://cognito-idp.<region>.amazonaws.com/<user-pool-id>", // Issuer URL (Cognito User Pool)
        //   "cognito:username": "user@example.com", // Cognito username
        //   "origin_jti": "original-jwt-id",       // Original JWT ID for tracking
        //   "aud": "client-id",                    // Audience (Client ID of the application)
        //   "event_id": "event-id",                // Unique event ID
        //   "token_use": "id",                     // Token type (ID token)
        //   "auth_time": 1234567890,               // Time the user was authenticated (Unix timestamp)
        //   "exp": 1234569990,                     // Expiration time (Unix timestamp)
        //   "iat": 1234567890,                     // Issued at time (Unix timestamp)
        //   "jti": "jwt-id",                       // Unique identifier for this token (JWT ID)
        //   "email": "user@example.com"            // User's email address
        // }

        // save the refresh token in a cookie or local storage and use it to refresh the access token when you need to
        console.log("refresh token: " + session.getRefreshToken().getToken());
        setLoading(false);
      },
      onFailure: (error) => {
        console.error("Error:", (error as CognitoSignInError).code);
        setLoading(false);
      },
    });
  };

  const getSession = () => {
    const cognitoUser = userPool.getCurrentUser();
    if (!cognitoUser) {
      console.error("No user is currently logged in");
      return;
    }
    if (cognitoUser) {
      cognitoUser.getSession((error: any, session: CognitoUserSession) => {
        if (error || !session) {
          console.error("Error:", error);
          return;
        }
        console.log("session", session);
      });
    }
  };

  const logout = () => {
    const cognitoUser = userPool.getCurrentUser();
    if (cognitoUser) {
      cognitoUser.signOut();
    }
    console.log("logged out");
  };

  // logic would need to be implemented on the client side to refresh the session if the access token expires
  const refreshSession = () => {
    const cognitoUser = userPool.getCurrentUser();

    if (cognitoUser) {
      // Get the current session to retrieve the refresh token
      cognitoUser.getSession((error: any, session: any) => {
        if (error || !session) {
          console.error("Error retrieving session:", error);
          return;
        }

        const refreshToken = session.getRefreshToken();

        // Use the refresh token to refresh the session
        cognitoUser.refreshSession(refreshToken, (error, newSession) => {
          if (error) {
            console.error("Error refreshing session:", error);
            return;
          }

          console.log("Session refreshed successfully");
          console.log(
            "New Access Token:",
            newSession.getAccessToken().getJwtToken()
          );
          console.log("New ID Token:", newSession.getIdToken().getJwtToken());
          console.log(
            "New Refresh Token:",
            newSession.getRefreshToken().getToken()
          );
        });
      });
    } else {
      console.error("No user is currently logged in");
    }
  };

  return (
    <div className="p-8 w-full flex flex-col items-start">
      <button
        disabled={loading}
        className="py-2 px-3 rounded-sm bg-white/25 hover:bg-white/40"
        onClick={() =>
          formState === "register"
            ? setFormState("login")
            : setFormState("register")
        }
      >
        toggle form
      </button>
      <form
        className="flex flex-col gap-2 mt-6 bg-white/10 p-4 rounded"
        onSubmit={formState === "register" ? register : login}
      >
        <input
          disabled={loading}
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="Email"
          className="py-2 px-3 rounded-sm bg-white/25"
        />
        <input
          disabled={loading}
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
          className="py-2 px-3 rounded-sm bg-white/25"
        />
        <button
          disabled={loading}
          type="submit"
          className="py-2 px-3 rounded-sm bg-white/25 hover:bg-white/40"
        >
          {formState}
        </button>
      </form>
      <button
        className="py-2 px-3 rounded-sm bg-white/25 hover:bg-white/40 mt-6"
        onClick={getSession}
      >
        get session
      </button>
      <button
        className="py-2 px-3 rounded-sm bg-orange-400/40 hover:bg-orange-400/60 mt-6"
        onClick={async () => {
          try {
            userPool
              .getCurrentUser()
              ?.getSession(async (error: any, session: CognitoUserSession) => {
                if (error || !session) {
                  console.error("Error:", error);
                  return;
                }
                console.log(session.getIdToken().getJwtToken());
                const res = await fetch(
                  `${process.env.NEXT_PUBLIC_API_URL}/`,
                  // "https://fvqg7urab2.execute-api.us-east-1.amazonaws.com/Prod",
                  {
                    method: "GET",
                    headers: {
                      Authorization:
                        // "Bearer eyJraWQiOiJNUGNMblNKRXNYWHpWdjZUd3NUTStmeFZBVHViK1dPMytPT3A5QjdxMzNFPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI4NDg4ODQ5OC04MDUxLTcwYTctYTU0My0yNjEyNGNlMzJlODMiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfU3B1eTNqWWVYIiwiY29nbml0bzp1c2VybmFtZSI6Ik1hdHRoZXcuU3dlZW5leTAwMUBnbWFpbC5jb20iLCJvcmlnaW5fanRpIjoiMWU2YjIwZjQtYTA4OS00NzQxLWJjMTktOTEzZDhmNDNlYzVlIiwiYXVkIjoiMXM0NHR2dGRuaHVmZmw0azJzMjJvaDA1ZWYiLCJldmVudF9pZCI6ImIxMWNmOGI3LTE4NjYtNGYwYy05ZjQ0LTA4ZjdlODBkM2Q4MiIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNzI1OTA5MDY3LCJleHAiOjE3MjU5MTI2NjcsImlhdCI6MTcyNTkwOTA2NywianRpIjoiMzVhYTU5MWEtODU4MS00MTMxLThlMmItZDg5ZmEwMWQwM2UyIiwiZW1haWwiOiJNYXR0aGV3LlN3ZWVuZXkwMDFAZ21haWwuY29tIn0.lZUnZXrSgK3r3BMx25yE6vgJ_IbmVwqY6_ILfBuYWPLq4WxmA1h6ROrrJQ-J6FM0gArcuCG4wl0mKhhS5Hy2bVD11JFak5smLn3WHfmtB5KzBqt-hFxe6asSzpI1rDEVnsX-FAhOKaATrDEqdhhwSzsPoPrmFNwT4qbOwar6j3Du4GWFPyS9flZ04LIIgvLBahCfGirRuXszkJJ2fDEdctsYuLJNNAcZslO9-SG8Xe0BeLBXpK8k5DX6Lv3l3mqVRm1uvMgoutte1LL98ue2JxLQbnIqp73tEH1r5c7pxJ2TRCVQ5aOLPNuyKUCRSDLLNhXRkHvLzl33qPRU02sexg",
                        `Bearer ${session.getIdToken().getJwtToken()}`,
                    },
                  }
                );
                const data = await res.json();
                console.log(data);
              });
          } catch (error) {
            console.error(error);
          }
        }}
      >
        Test Function 1
      </button>
      <button
        className="py-2 px-3 rounded-sm bg-orange-400/40 hover:bg-orange-400/60 mt-6"
        onClick={async () => {
          try {
            const res = await fetch(
              `${process.env.NEXT_PUBLIC_API_URL}/test-function-2`,
              {
                method: "GET",
                headers: {
                  Authorization: `Bearer ${userPool
                    .getCurrentUser()
                    ?.getSignInUserSession()
                    ?.getIdToken()
                    ?.getJwtToken()}`,
                },
              }
            );
            const data = await res.json();
            console.log(data);
          } catch (error) {
            console.error(error);
          }
        }}
      >
        Test Function 2
      </button>
      <button
        className="py-2 px-3 rounded-sm bg-red-400/50 hover:bg-red-400/75 mt-6"
        onClick={logout}
      >
        logout
      </button>
    </div>
  );
}
