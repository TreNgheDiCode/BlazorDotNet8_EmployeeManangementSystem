using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Components.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace ClientLibrary.Helpers
{
    public class CustomAuthenticationStateProvider(LocalStorageService localStorageService) : AuthenticationStateProvider
    {
        // This is the anonymous user
        private readonly ClaimsPrincipal anonymous = new(new ClaimsIdentity());
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            // Get the token from the local storage
            var stringToken = await localStorageService.GetToken();

            // If the token is null or empty, return the anonymous user
            if (string.IsNullOrEmpty(stringToken))
            {
                return await Task.FromResult(new AuthenticationState(anonymous));
            }

            // Deserialize the token
            var deserializeToken = Serializations.DeserializeJsonString<UserSession>(stringToken);
            if (deserializeToken == null)
            {
                // If the token is not valid, return the anonymous user
                return await Task.FromResult(new AuthenticationState(anonymous));
            }

            // Decrypt the token
            var getUserClaims = DecryptToken(deserializeToken.Token!);
            if (getUserClaims == null)
            {
                return await Task.FromResult(new AuthenticationState(anonymous));
            }

            // Set the claims principal
            var claimsPrincipal = SetClaimPrincipal(getUserClaims);
            return await Task.FromResult(new AuthenticationState(claimsPrincipal));
        }

        public async Task UpdateAuthenticationState(UserSession userSession)
        {
            // If the token is null or empty, return the anonymous user
            var claimsPrincipal = new ClaimsPrincipal();

            if (userSession.Token != null || userSession.RefreshToken != null)
            {
                // Serialize the user session
                var serializeSession = Serializations.SerializeObj(userSession);
                await localStorageService.SetToken(serializeSession);
                var getUserClaims = DecryptToken(userSession.Token!);
                claimsPrincipal = SetClaimPrincipal(getUserClaims);
            } else
            {
                await localStorageService.RemoveToken();
            }

            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
        }

        private static ClaimsPrincipal SetClaimPrincipal(CustomUserClaims claims)
        {
            if (claims.Email is null) return new ClaimsPrincipal();

            return new ClaimsPrincipal(new ClaimsIdentity(
                new List<Claim>
                {
                    new(ClaimTypes.NameIdentifier, claims.Id),
                    new(ClaimTypes.Name, claims.Name),
                    new(ClaimTypes.Email, claims.Email),
                    new(ClaimTypes.Role, claims.Role)
                }, "JwtAuth"
            ));
        }

        private static CustomUserClaims DecryptToken(string jwtToken)
        {
            // If the token is null or empty, return null
            if (string.IsNullOrEmpty(jwtToken))
            {
                return new CustomUserClaims();
            }

            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwtToken);
            // Get the claims from the token
            var userId = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
            var name = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            var email = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email);
            var role = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role);

            return new CustomUserClaims(userId!.Value, name!.Value, email!.Value, role!.Value);
        }
    }
}
