using AspNetCore.Security.CAS;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NLog;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CasTest
{
    public class Startup
    {
        private static readonly ILogger _logger = LogManager.GetCurrentClassLogger();

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.ConfigureNonBreakingSameSiteCookies();

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(o =>
                {
                    o.LoginPath = new PathString("/login");

                    o.AccessDeniedPath = new PathString("/access-denied");

                    //不能自定义cookie，否则不成功
                    //o.Cookie = new CookieBuilder
                    //{
                    //    Name = ".AspNetCore.CasSample",
                    //};
                    o.Events = new CookieAuthenticationEvents
                    {
                        // Add user roles to the existing identity.  
                        // This example is giving every user "User" and "Admin" roles.
                        // You can use services or other logic here to determine actual roles for your users.
                        OnSigningIn = context =>
                            {
                                _logger.Info("OnSigningIn");

                                // Use `GetRequiredService` if you have a service that is using DI or an EF Context.
                                // var username = context.Principal.Identity.Name;
                                // var userSvc = context.HttpContext.RequestServices.GetRequiredService<UserService>();
                                // var roles = userSvc.GetRoles(username);

                                // Hard coded roles.

                                var roles = new[] { "User", "Admin" };

                                // `AddClaim` is not available directly from `context.Principal.Identity`.
                                // We can add a new empty identity with the roles we want to the principal. 
                                var identity = new ClaimsIdentity();

                                foreach (var role in roles)
                                {
                                    identity.AddClaim(new Claim(ClaimTypes.Role, role));
                                }

                                context.Principal.AddIdentity(identity);

                                return Task.FromResult(0);
                            },
                        OnSigningOut = context =>
                        {
                            // Single Sign-Out
                            _logger.Info("OnSigningOut");

                            return Task.CompletedTask;
                        }
                    };
                })
                .AddCAS(o =>
                {
                    o.CasServerUrlBase = Configuration["CasBaseUrl"];   // Set in `appsettings.json` file.
                    o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    o.Events = new CasEvents
                    {
                        OnCreatingTicket = context =>
                        {
                            _logger.Info("OnCreatingTicket");

                            return Task.CompletedTask;
                        },
                        OnRemoteFailure = context =>
                        {
                            var failure = context.Failure;
                            _logger.Info(failure, failure.Message);
                            return Task.CompletedTask;
                        }
                    };
                });
            services.AddControllersWithViews();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseCookiePolicy();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
