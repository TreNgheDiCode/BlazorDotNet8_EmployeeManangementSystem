using BaseLibrary.DTOs;
using ClientLibrary.Services.Contracts;
using System.Net;
using System.Net.Http.Headers;

namespace ClientLibrary.Helpers
{
    public class CustomHttpHandler(GetHttpClient getHttpClient, LocalStorageService localStorageService, IUserAccountService userAccountService) : DelegatingHandler
    {
        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Check if the request is for login, register or refresh-token
            bool loginUrl = request.RequestUri!.AbsoluteUri.Contains("login");
            bool registerUrl = request.RequestUri!.AbsoluteUri.Contains("register");
            bool refreshToken = request.RequestUri!.AbsoluteUri.Contains("refresh-token");

            // If the request is for login, register or refresh-token, send the request
            if (loginUrl || registerUrl || refreshToken)
            {
                return await base.SendAsync(request, cancellationToken);
            }

            var result = await base.SendAsync(request, cancellationToken);
            if (result.StatusCode == HttpStatusCode.Unauthorized)
            {
                // Get the token from the local storage
                var stringToken = await localStorageService.GetToken();
                if (stringToken == null) return result;

                // Get the token from the request header
                string token = string.Empty;
                try
                {
                    token = request.Headers.Authorization!.Parameter!;
                } catch { }

                // Deserialize the token
                var deserializeToken = Serializations.DeserializeJsonString<UserSession>(stringToken);
                if (deserializeToken == null) return result;

                // If the token is empty, set the token from the local storage
                if (string.IsNullOrEmpty(token))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", deserializeToken.Token);
                    return await base.SendAsync(request, cancellationToken);
                }

                // If the token is expire, get a new token
                var newJwtToken = await GetRefreshTokenAsync(deserializeToken.RefreshToken!);
                if (string.IsNullOrEmpty(newJwtToken)) return result;

                // Set the new token
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newJwtToken);
                return await base.SendAsync(request, cancellationToken);
            }
            return result;
        }

        private async Task<string> GetRefreshTokenAsync(string refreshToken)
        {
            // Get a new token
            var result = await userAccountService.RefreshTokenAsync(new RefreshToken() { Token = refreshToken });
            // If the result is empty, return an empty string
            string serializedToken = Serializations.SerializeObj(new UserSession() { Token = result.Token, RefreshToken = result.RefreshToken });
            await localStorageService.SetToken(serializedToken);

            return result.Token;
        }
    }
}
