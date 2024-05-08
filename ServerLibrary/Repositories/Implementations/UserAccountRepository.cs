using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ServerLibrary.Repositories.Implementations
{
    public class UserAccountRepository(IOptions<JwtSection> config, AppDbContext appDbContext) : IUserAccount
    {
        public async Task<GeneralResponse> CreateAsync(Register user)
        {
            // Check if model is empty
            if (user is null) return new GeneralResponse(false, "Model is empty");

            // Check if user already exists
            var checkUser = await FindUserByEmail(user.Email);
            if (checkUser is not null) return new GeneralResponse(false, "User already exists");

            // Create new user
            var applicationUser = await AddToDatabase(new ApplicationUser()
            {
                Fullname = user.Fullname,
                Email = user.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password),
            });

            // Check, create and assign admin role
            var checkAdminRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(r => r.Name!.Equals(Constants.Admin));
            if (checkAdminRole is null)
            {
                var createAdminRole = await AddToDatabase(new SystemRole() { Name = Constants.Admin});
                await AddToDatabase(new UserRole() { RoleId = createAdminRole.Id, UserId = applicationUser.Id });
                return new GeneralResponse(true, "Initial admin account created!");
            }

            // Check, create and assign user role
            var checkUserRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(r => r.Name!.Equals(Constants.User));
            SystemRole response = new();
            if (checkUserRole is null)
            {
                response = await AddToDatabase(new SystemRole() { Name = Constants.User });
                await AddToDatabase(new UserRole() { RoleId = response.Id, UserId = applicationUser.Id });
                return new GeneralResponse(true, "Initial user account created!");
            } else
            {
                await AddToDatabase(new UserRole() { RoleId = checkUserRole.Id, UserId = applicationUser.Id });
            }

            return new GeneralResponse(true, "User created successfully!");
        }

        public async Task<LoginResponse> SignInAsync(Login user)
        {
            // Check if model is empty
            if (user is null) return new LoginResponse(false, "Model is empty");

            // Check if user exists
            var applicationUser = await FindUserByEmail(user.Email!);
            if (applicationUser is null) return new LoginResponse(false, "User not found");

            // Check if password is correct
            if (!BCrypt.Net.BCrypt.Verify(user.Password, applicationUser.Password)) 
                return new LoginResponse(false, "Invalid credentials");

            // Verify roles
            var getUserRole = await FindUserRole(applicationUser.Id);
            if (getUserRole is null) return new LoginResponse(false, "User role not found");

            var getRoleName = await FindRoleName(getUserRole.RoleId);
            if (getRoleName is null) return new LoginResponse(false, "Role not found");

            // Generate token
            string jwtToken = GenerateToken(applicationUser, getRoleName.Name!);
            string refreshToken = GenerateRefreshToken();

            // Check if user has a refresh token
            var checkRefreshToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(x => x.UserId == applicationUser.Id);

            if (checkRefreshToken is not null)
            {
                checkRefreshToken.Token = refreshToken;
                await appDbContext.SaveChangesAsync();
            } else
            {
                await AddToDatabase(new RefreshTokenInfo() { Token = refreshToken, UserId = applicationUser.Id });
            }

            return new LoginResponse(true, "Login successful", jwtToken, refreshToken);
        }

        private string GenerateToken(ApplicationUser user, string role)
        {
            // Token headers & signature
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            // Token payload
            // Claims
            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Fullname!),
                new Claim(ClaimTypes.Email, user.Email!),
                new Claim(ClaimTypes.Role, role),
            };
            // Token descriptor
            var token = new JwtSecurityToken(
                issuer: config.Value.Issuer,
                audience: config.Value.Audience,
                claims: userClaims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<UserRole> FindUserRole(int userId)
        {
            return await appDbContext.UserRoles.FirstOrDefaultAsync(x => x.UserId == userId);
        }

        private async Task<SystemRole> FindRoleName(int roleId)
        {
            return await appDbContext.SystemRoles.FirstOrDefaultAsync(x => x.Id == roleId);
        }

        private static string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

        private async Task<ApplicationUser> FindUserByEmail(string email)
        {
            return await appDbContext.ApplicationUsers.FirstOrDefaultAsync(x => x.Email!.ToLower().Equals(email!.ToLower()));
        }

        private async Task<T> AddToDatabase<T>(T model)
        {
            var result = appDbContext.Add(model!);
            await appDbContext.SaveChangesAsync();
            return (T)result.Entity;
        }

        public async Task<LoginResponse> RefreshTokenAsync(RefreshToken refreshToken)
        {
            // Check if model is empty
            if (refreshToken is null) return new LoginResponse(false, "Model is empty");


            // Check if refresh token exists
            var findToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(x => x.Token!.Equals(refreshToken.Token));
            if (findToken is null) return new LoginResponse(false, "Token not found");

            // Get user details
            var user = await appDbContext.ApplicationUsers.FirstOrDefaultAsync(x => x.Id == findToken.UserId);
            if (user is null) return new LoginResponse(false, "User not found");

            // Verify roles
            var getUserRole = await FindUserRole(user.Id);
            if (getUserRole is null) return new LoginResponse(false, "User role not found");

            var getRoleName = await FindRoleName(getUserRole.RoleId);
            if (getRoleName is null) return new LoginResponse(false, "Role not found");

            // Generate token
            string jwtToken = GenerateToken(user, getRoleName.Name!);
            string newRefreshToken = GenerateRefreshToken();

            // Check if user has a refresh token
            var checkRefreshToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(x => x.UserId == user.Id);
            if (checkRefreshToken is null) return new LoginResponse(false, "User has not signed in");

            // Update refresh token
            checkRefreshToken.Token = newRefreshToken;
            await appDbContext.SaveChangesAsync();

            return new LoginResponse(true, "Token refreshed", jwtToken, newRefreshToken);
        }
    }
}
