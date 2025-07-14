using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace RefitDemo.Common.Services
{
    internal class AuthHeaderHandler: HttpClientHandler
    {
        //private readonly ITenantProvider tenantProvider;
        //private readonly IAuthTokenStore authTokenStore;

        //public AuthHeaderHandler(ITenantProvider tenantProvider, IAuthTokenStore authTokenStore)
        //{
        //    this.tenantProvider = tenantProvider ?? throw new ArgumentNullException(nameof(tenantProvider));
        //    this.authTokenStore = authTokenStore ?? throw new ArgumentNullException(nameof(authTokenStore));
        //    // InnerHandler must be left as null when using DI, but must be assigned a value when
        //    // using RestService.For<IMyApi>
        //    // InnerHandler = new HttpClientHandler();
        //}
        
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            //var token = await authTokenStore.GetToken();

            //potentially refresh token here if it has expired etc.

           // request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            //request.Headers.Add("X-Tenant-Id", tenantProvider.GetTenantId());

            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }
}
