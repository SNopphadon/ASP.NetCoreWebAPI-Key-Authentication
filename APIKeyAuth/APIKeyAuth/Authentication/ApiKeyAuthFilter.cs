using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace APIKeyAuth.Authentication
{
    public class ApiKeyAuthFilter :Attribute, IAuthorizationFilter
    {
        private readonly IConfiguration _configuration;
        public ApiKeyAuthFilter(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            if (!context.HttpContext.Request.Headers.TryGetValue(AuthConstants.ApiKeyHeaderName, out
                var extractedApiKey))
            {
                context.Result = new UnauthorizedObjectResult("API Key missing");
                return;
            }
            var actualApiKey = _configuration.GetValue<string>("ApiKey")!;
            if (!actualApiKey.Equals(extractedApiKey))
            {
                context.Result = new UnauthorizedObjectResult("Invalid API Key");
                return;
            }
        }
    }
}
