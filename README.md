# TokenService (Azure Functions)

TokenService is an Azure Functions app responsible for generating and validating JWT access tokens for the Ventixe platform.

## Features
- **/api/GenerateToken** (POST): Generates a JWT access token for a user.
- **/api/ValidateToken** (POST): Validates a JWT access token and verifies the user's identity.

## Environment Variables (`local.settings.json`)
```json
{
  "Issuer": "localhost...",
  "Audience": "Ventixe",
  "SecretKey": "..."
}
```

## Example Requests

### Generate Token
POST `/api/GenerateToken`
```json
{
  "userId": "...",
  "email": "user@example.com",
  "role": "User"
}
```
**Response:**
```json
{
  "succeeded": true,
  "accessToken": "...",
  "message": "Token generated for user user@example.com."
}
```

### Validate Token
POST `/api/ValidateToken`
```json
{
  "userId": "...",
  "accessToken": "..."
}
```
**Response:**
```json
{
  "succeeded": true,
  "message": "Token is valid for user@example.com."
}
```

## Important Notes
- JWT configuration must be identical across all services for tokens to be accepted.
- Tokens include claims: `nameid` (userId), `email`, and `role`.
- The `message` field in responses displays the user's email (if provided), otherwise the userId.
