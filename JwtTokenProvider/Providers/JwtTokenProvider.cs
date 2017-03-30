using System;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Identity;
using JwtTokenProvider.Models;
using System.Collections.Generic;

namespace JwtTokenProvider.Providers
{
    public class JwtTokenProvider
    {
        private readonly RequestDelegate _next;
        private readonly JwtTokenProviderOptions _options;
        private readonly JsonSerializerSettings _serializerSettings;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public JwtTokenProvider(RequestDelegate next, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IOptions<JwtTokenProviderOptions> options)
        {
            _userManager = userManager;
            _signInManager = signInManager;

            _next = next;

            _options = options.Value;
            ThrowIfInvalidOptions(_options);

            _serializerSettings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented
            };
        }

        public Task Invoke(HttpContext context)
        {
            // If the request path doesn't match, skip
            if (!context.Request.Path.Equals(_options.Path, StringComparison.Ordinal))
            {
                return _next(context);
            }

            // Request must be POST with Content-Type: application/x-www-form-urlencoded
            if (!context.Request.Method.Equals("POST")
               || !context.Request.HasFormContentType)
            {
                context.Response.StatusCode = 400;
                return context.Response.WriteAsync("Bad request.");
            }

            return GenerateToken(context);
        }

        private async Task GenerateToken(HttpContext context)
        {
            var username = context.Request.Form["username"];
            var password = context.Request.Form["password"];

            IList<Claim> userclaims = new List<Claim>();

            var result = await _signInManager.PasswordSignInAsync(username, password, false, false);
            if (result.Succeeded)
            {
                var user = await _userManager.FindByNameAsync(username);
                userclaims = await _userManager.GetClaimsAsync(user);

                var now = DateTime.UtcNow;

                userclaims.Add(new Claim(JwtRegisteredClaimNames.Sub, username));
                userclaims.Add(new Claim(JwtRegisteredClaimNames.Jti, await _options.NonceGenerator()));
                userclaims.Add(new Claim(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUniversalTime().ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64));

                // Create the JWT and write it to a string
                var jwt = new JwtSecurityToken(
                    issuer: _options.Issuer,
                    audience: _options.Audience,
                    claims: userclaims,
                    notBefore: now,
                    expires: now.Add(_options.Expiration),
                    signingCredentials: _options.SigningCredentials);
                var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

                var response = new
                {
                    access_token = encodedJwt,
                    expires_in = (int)_options.Expiration.TotalSeconds
                };

                // Serialize and return the response
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonConvert.SerializeObject(response, _serializerSettings));
            }
            //else
            //{
            //    var response = new
            //    {
            //        message = "Username or Password is invalid"
            //    };
            //    context.Response.ContentType = "application/json";
            //    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            //}
        }

        private static void ThrowIfInvalidOptions(JwtTokenProviderOptions options)
        {
            if (string.IsNullOrEmpty(options.Path))
            {
                throw new ArgumentNullException(nameof(JwtTokenProviderOptions.Path));
            }

            if (string.IsNullOrEmpty(options.Issuer))
            {
                throw new ArgumentNullException(nameof(JwtTokenProviderOptions.Issuer));
            }

            if (string.IsNullOrEmpty(options.Audience))
            {
                throw new ArgumentNullException(nameof(JwtTokenProviderOptions.Audience));
            }

            if (options.Expiration == TimeSpan.Zero)
            {
                throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(JwtTokenProviderOptions.Expiration));
            }

            if (options.SigningCredentials == null)
            {
                throw new ArgumentNullException(nameof(JwtTokenProviderOptions.SigningCredentials));
            }

            if (options.NonceGenerator == null)
            {
                throw new ArgumentNullException(nameof(JwtTokenProviderOptions.NonceGenerator));
            }
        }

    }
}
