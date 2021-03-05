using CasTest.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using NLog;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;

namespace CasTest.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpClientFactory _clientFactory;
        private readonly IConfiguration _configuration;
        private static readonly ILogger _logger = LogManager.GetCurrentClassLogger();


        public HomeController(IConfiguration configuration, IHttpClientFactory clientFactory)
        {
            _configuration = configuration;
            _clientFactory = clientFactory;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Error()
        {
            return View();
        }

        [HttpGet("access-denied")]
        public IActionResult AccessDenied()
        {
            return View();
        }

        /// <summary>
        /// The authorize tag can also be put on the controller level to require 
        /// authorization on all of the controller's actions.
        /// </summary>
        [Authorize]
        public IActionResult AuthorizedPage(string foo)
        {
            return View();
        }

        [Authorize(Roles = "Admin")]
        public IActionResult AdminOnly()
        {
            return View();
        }

        /// <summary>
        /// Immediately invokes a CAS challenge.  The Cookie middleware uses this page as
        /// the login page that it will send users to if they are not signed in.
        /// </summary>
        [AllowAnonymous]
        [HttpGet("login")]
        public async Task Login(string returnUrl)
        {
            var props = new AuthenticationProperties { RedirectUri = returnUrl };
            await HttpContext.ChallengeAsync("CAS", props);
        }

        /// <summary>
        /// Removes authentication cookie and redirects back to the home page.
        /// </summary>
        [HttpGet("logout")]
        public async Task Logout()
        {
            _logger.Info("Logout");
            // Removes the user's auth cookie for this site and domain. 
            await HttpContext.SignOutAsync();

            // Do a full CAS logout.  
            // This removes the user's CAS auth cookie from the CAS domain.
            //return Redirect($"{_configuration["CasBaseUrl"]}/logout");

            // Send them back to the home page.  
            // The user will remain signed into CAS. This means that if they again 
            // click to `AuthorizedPage`, they would be sent to `login` and challenged,
            // but the CAS login would be transparent/instant.
            //return RedirectToAction("Index");

            //退出服务前端登录
            //var handler = new HttpClientHandler() { UseCookies = true };
            //var client2 = new HttpClient(handler);// { BaseAddress = baseAddress };

            //var client = _clientFactory.CreateClient();
            //var url = $"{_configuration["CasBaseUrl"]}/logout";
            //_logger.Info(url);
            //HttpResponseMessage res = await client2.GetAsync(url);
            //_logger.Info(res);

            //var actionContext = new ActionContext(HttpContext, HttpContext.GetRouteData(), this.ControllerContext.ActionDescriptor);
            //Redirect($"{_configuration["CasBaseUrl"]}/logout").ExecuteResult(actionContext);
        }
    }
}
