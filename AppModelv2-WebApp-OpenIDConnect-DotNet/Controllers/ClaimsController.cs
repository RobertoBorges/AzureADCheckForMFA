using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace AppModelv2_WebApp_OpenIDConnect_DotNet.Controllers
{
    [Authorize]
    public class ClaimsController : Controller
    {
        /// <summary>
        /// Add user's claims to viewbag
        /// </summary>
        /// <returns></returns>
        public ActionResult Index()
        {
            var userClaims = User.Identity as System.Security.Claims.ClaimsIdentity;

            var stsDiscoveryEndpoint = String.Format(CultureInfo.InvariantCulture, "https://login.microsoftonline.com/{0}/.well-known/openid-configuration", "b9f303d6-1732-4928-95bd-26243f271827");
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, new OpenIdConnectConfigurationRetriever());
            var config = configManager.GetConfigurationAsync();

            var result = Request.GetOwinContext().Authentication.AuthenticateAsync("Cookies");
            string token = result.Result.Properties.Dictionary["id_token"];

            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(token);

            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = jwtSecurityToken.SecurityKey,
                RequireExpirationTime = true,
                RequireAudience = false,
                ValidateLifetime = true,
                ValidateAudience = true,
                ValidateIssuer = true,
                AuthenticationType = "Test"
            };

            if (ValidateToken(token, tokenValidationParameters))
            {
                var TokenInfo = new Dictionary<string, string>();
                jwtSecurityToken = handler.ReadJwtToken(token);
                var claims = jwtSecurityToken.Claims.ToList();

                foreach (var claim in claims)
                {
                    TokenInfo.Add(claim.Type, claim.Value);
                }

                string sub = jwtSecurityToken.Subject;
                string iss = jwtSecurityToken.Issuer;
                DateTime iat = jwtSecurityToken.IssuedAt;
                List<string> audiences = new List<string>(jwtSecurityToken.Audiences);
                DateTime exp = jwtSecurityToken.ValidTo;
                string bar;
                bool ifBar = TokenInfo.TryGetValue("foo", out bar);
                Console.WriteLine("Subject: " + sub);
                Console.WriteLine("Issuer: " + iss);
                Console.WriteLine("Issued At: " + iat);
                foreach (var member in audiences)
                {
                    Console.WriteLine("Audience: " + member);
                }
                Console.WriteLine("Expiration: " + exp);
                Console.WriteLine("foo: " + bar);
            }
            Console.ReadLine();

            //You get the user’s first and last name below:
            ViewBag.Name = userClaims?.FindFirst("name")?.Value;

            // The 'preferred_username' claim can be used for showing the username
            ViewBag.Username = userClaims?.FindFirst("preferred_username")?.Value;

            // The subject/ NameIdentifier claim can be used to uniquely identify the user across the web
            ViewBag.Subject = userClaims?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

            // TenantId is the unique Tenant Id - which represents an organization in Azure AD
            ViewBag.TenantId = userClaims?.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid")?.Value;

            return View();
        }

        private bool ValidateToken(string token, TokenValidationParameters tvp)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();

                SecurityToken securityToken;
                ClaimsPrincipal principal = handler.ValidateToken(token, tvp, out securityToken);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }

    }
}