using Refit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace RefitDemo.Common.Services
{
    public static class ApiClientFactory
    {
        public static T Create<T>(string baseUrl)
        {
            var httpClient = new HttpClient(new HttpClientHandler()
            {
                // Uncomment the following line to disable proxy usage
                // UseProxy = false
            })
            {
                BaseAddress = new Uri(baseUrl),
                Timeout = TimeSpan.FromSeconds(30)
            };

            // 添加默认请求头
            httpClient.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

            return RestService.For<T>(httpClient);
        }
    }
}
