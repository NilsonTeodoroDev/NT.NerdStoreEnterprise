using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace NSE.WebApp.MVC.Extensions
{
    public interface IUser
    {
        string Name { get; }
        Guid ObterUserId();
        string ObterUserEmail();
        string ObterUserToken();
        bool EstaAutenticado();
        bool PossuiRole(string role);
        IEnumerable<Claim> ObterClaims();
        HttpContext ObterHttpContext();
    }

    public class AspNetUser : IUser
    {
        private readonly IHttpContextAccessor _acessor;

        public AspNetUser(IHttpContextAccessor acessor)
        {
            _acessor = acessor;
        }

        public string Name => _acessor.HttpContext.User.Identity.Name;

        public Guid ObterUserId() => EstaAutenticado() ? Guid.Parse(_acessor.HttpContext.User.GetUserId()) : Guid.Empty;

        public string ObterUserEmail() => EstaAutenticado() ? _acessor.HttpContext.User.GetUserEmail() : "";

        public string ObterUserToken() => EstaAutenticado() ? _acessor.HttpContext.User.GetUserToken() : "";

        public bool EstaAutenticado() => _acessor.HttpContext.User.Identity.IsAuthenticated;

        public bool PossuiRole(string role) => _acessor.HttpContext.User.IsInRole(role);

        public IEnumerable<Claim> ObterClaims() => _acessor.HttpContext.User.Claims;

        public HttpContext ObterHttpContext() => _acessor.HttpContext;
    }

    public static class ClaimsPrincipalExtensions
    {
        public static string GetUserId(this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentException(nameof(principal));
            }

            var claim = principal.FindFirst("sub");
            return claim?.Value;
        }

        public static string GetUserEmail(this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentException(nameof(principal));
            }

            var claim = principal.FindFirst("email");
            return claim?.Value;
        }

        public static string GetUserToken(this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentException(nameof(principal));
            }

            var claim = principal.FindFirst("JWT");
            return claim?.Value;
        }
    }
}
