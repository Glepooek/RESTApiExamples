# RESTApiExamples

Refit是一个受Square Retrofit库启发的库，它将您的REST API转变为实时接口：

```c#
public interface IGitHubApi
{
    [Get("/users/{user}")]
    Task<User> GetUser(string user);
}
```

RestService类生成IGitHubApi的实现，该实现使用httpClient进行调用：

```c#
var gitHubApi = RestService.For<IGitHubApi>("https://api.github.com");
var octocat = await gitHubApi.GetUser("octocat");
```

.NET Core支持通过httpClientFactory注册：

```c#
services
    .AddRefitClient<IGitHubApi>()
    .ConfigureHttpClient(c => c.BaseAddress = new Uri("https://api.github.com"));
```

目录
这在哪里工作？
6.x中的突破性变化
API属性
查询串
动态查询字符串参数
作为Querystring参数的集合
取消转义Querystring参数
自定义查询串参数格式
正文内容
缓冲和内容长度标题
JSON内容
XML内容
表格职位
设置请求标头
静态标题
动态标题
持票人身份验证
使用DelegatingHandlers减少标头样板（授权标头工作示例）
重新定义标题
移除页眉
将状态传递到委托处理程序
对波莉和波莉的支持。上下文
目标接口类型
调用的Refit客户端界面上方法的MethodInfo
Multipart uploads
检索响应
使用泛型接口
接口继承
标题继承
默认接口方法
使用httpClientFactory
提供自定义的httpClient
处理异常
返回Task<IApiResponse>、Task &amp; IapiResponse <T>&amp;或Task &amp; ApiResponse <T>&amp;时
返回任务时<T>
提供自定义ExceptionFactory
用Serilog解构ApiExcept
这在哪里工作？
Refit目前支持以下平台和任何.NET Standard 2.0目标：

UWP
Xamarin.Android
Xamarin.Mac
Xamarin.iOS
桌面.NET 4.6.1
.NET 6 / 8
Blazor
Uno平台
SDK要求
8.0.x中的更新
修复了一些遇到的问题，这会导致一些突破性的变化。有关完整详细信息，请参阅发布。

V6.x.x
Refit 6需要Visual Studio 16.8或更高版本，或者.NET SDK 5.0.100或更高版本。它可以针对任何.NET标准2.0平台。

Refit 6不支持NuGet引用的旧的packages.config格式（因为它们不支持分析器/源代码生成器）。您必须迁移到PackageReference才能使用Refit v6及更高版本。

6.x中的突破性变化
Refit 6使System.Text.Json成为默认的SON序列化器。如果您想继续使用Newtonsoft.Json，请添加Refit.Newtonsoft.Json NuGet包，并将您的ContentSerializer设置为RefitPoints实例上的NewtonsoftJsonContentSerializer。System.Text.Json速度更快，占用内存更少，但并非所有功能都受到支持。迁移指南包含更多详细信息。

IContentSerializer更名为IhttpContentSerializer，以更好地反映其目的。此外，它的两个方法被重命名为SerializeAsmat<T>-&gt; TohttpContent<T>和SerializeAsmat<T>-&gt; FromhttpContentAsmat<T>。这些内容的任何现有实现都需要更新，尽管变化应该很小。

6.3中的更新
Refit 6.3通过XtmlContentSerializer将ML序列化拆分为一个单独的包Refit.html。这是为了在使用Retit with Web Assembly（WASM）应用程序时减少依赖项大小。如果您需要HTML，请添加对Refit.html的引用。

API属性
每个方法都必须有一个提供请求方法和相对URL的HTTP属性。有六个内置注释：获取、发布、放置、删除、补丁和头部。资源的相对URL在注释中指定。

[Get("/users/list")]
您还可以在URL中指定查询参数：

[Get("/users/list?sort=desc")]
可以使用方法上的替换块和参数动态更新请求URL。替换块是一个由{和}包围的字母数字字符串。

如果参数的名称与URL路径中的名称不匹配，请使用AliasAs属性。

[Get("/group/{id}/users")]
Task<List<User>> GroupList([AliasAs("id")] int groupId);
请求url还可以将替换块绑定到自定义对象

[Get("/group/{request.groupId}/users/{request.userId}")]
Task<List<User>> GroupList(UserGroupRequest request);

class UserGroupRequest{
    int groupId { get;set; }
    int userId { get;set; }
}
未指定为URL替代的参数将自动用作查询参数。这与Retrofit不同，Retrofit中所有参数都必须显式指定。

参数名称和URL参数之间的比较不区分大小写，因此，如果您在路径/group/{groupid}/show中命名参数groupId，则可以正常工作。

[Get("/group/{groupid}/users")]
Task<List<User>> GroupList(int groupId, [AliasAs("sort")] string sortOrder);

GroupList(4, "desc");
>>> "/group/4/users?sort=desc"
往返路线参数语法：使用双星号（**）涵盖所有参数语法时，不会对正斜杠进行编码。

在链路生成期间，路由系统对双星号（**）catch-all参数（例如，{** myparamaterName}）中捕获的值进行编码，但正斜杠除外。

往返路线参数类型必须为字符串。

[Get("/search/{**page}")]
Task<List<Page>> Search(string page);

Search("admin/products");
>>> "/search/admin/products"
查询串
动态查询串参数
如果将对象指定为查询参数，则所有非空的公共属性都将用作查询参数。这以前仅适用于GET请求，但现在已扩展到所有HTP请求方法，部分原因是Twitter的混合API坚持使用具有查询字符串参数的非GET请求。使用查询属性更改行为以“拉平”您的查询参数对象。如果使用此属性，您可以指定用于“拉平”对象的分隔符和后缀的值。

public class MyQueryParams
{
    [AliasAs("order")]
    public string SortOrder { get; set; }

    public int Limit { get; set; }

    public KindOptions Kind { get; set; }
}

public enum KindOptions
{
    Foo,

    [EnumMember(Value = "bar")]
    Bar
}


[Get("/group/{id}/users")]
Task<List<User>> GroupList([AliasAs("id")] int groupId, MyQueryParams params);

[Get("/group/{id}/users")]
Task<List<User>> GroupListWithAttribute([AliasAs("id")] int groupId, [Query(".","search")] MyQueryParams params);


params.SortOrder = "desc";
params.Limit = 10;
params.Kind = KindOptions.Bar;

GroupList(4, params)
>>> "/group/4/users?order=desc&Limit=10&Kind=bar"

GroupListWithAttribute(4, params)
>>> "/group/4/users?search.order=desc&search.Limit=10&search.Kind=bar"
如果使用词典，也存在类似的行为，但没有AliasAs属性的优势，当然也没有智能感知和/或类型安全。

您还可以使用[Query]指定查询字符串参数，并在非GET请求中将它们拉平，类似于：

[Post("/statuses/update.json")]
Task<Tweet> PostTweet([Query]TweetParams params);
其中TweetParams是POCO，并且属性还支持[AliasAs]属性。

作为Querystring参数的集合
使用查询属性指定在查询字符串中格式化集合的格式

[Get("/users/list")]
Task Search([Query(CollectionFormat.Multi)]int[] ages);

Search(new [] {10, 20, 30})
>>> "/users/list?ages=10&ages=20&ages=30"

[Get("/users/list")]
Task Search([Query(CollectionFormat.Csv)]int[] ages);

Search(new [] {10, 20, 30})
>>> "/users/list?ages=10%2C20%2C30"
您还可以在RefitSet中指定集合格式，默认情况下将使用该格式，除非在查询属性中明确定义。

var gitHubApi = RestService.For<IGitHubApi>("https://api.github.com",
    new RefitSettings {
        CollectionFormat = CollectionFormat.Multi
    });
取消转义Querystring参数
使用SecureUriForm属性指定查询参数是否应进行url逸出

[Get("/query")]
[QueryUriFormat(UriFormat.Unescaped)]
Task Query(string q);

Query("Select+Id,Name+From+Account")
>>> "/query?q=Select+Id,Name+From+Account"
自定义查询字符串参数格式
收件箱钥匙

要自定义查询键的格式，您有两个主要选项：

使用AliasAs属性：

您可以使用AliasAs属性指定属性的自定义密钥名称。此属性始终优先于您指定的任何密钥格式器。

public class MyQueryParams
{
    [AliasAs("order")]
    public string SortOrder { get; set; }

    public int Limit { get; set; }
}

[Get("/group/{id}/users")]
Task<List<User>> GroupList([AliasAs("id")] int groupId, [Query] MyQueryParams params);

params.SortOrder = "desc";
params.Limit = 10;

GroupList(1, params);
这将生成以下请求：

/group/1/users?order=desc&Limit=10
使用RefitSettings. UrlMechanterKeyFormatter属性：

默认情况下，Refit使用属性名称作为查询键，无需任何额外的格式。如果您想在所有查询键中应用自定义格式，则可以使用UrlMechanterKeyFormatter属性。请记住，如果属性具有AliasAs属性，则无论格式程序如何，都将使用该属性。

下面的示例使用内置CamelCaseUrlDataberKeyFormatter：

public class MyQueryParams
{
    public string SortOrder { get; set; }

    [AliasAs("queryLimit")]
    public int Limit { get; set; }
}

[Get("/group/users")]
Task<List<User>> GroupList([Query] MyQueryParams params);

params.SortOrder = "desc";
params.Limit = 10;
该请求看起来像：

/group/users?sortOrder=desc&queryLimit=10
注意：AliasAs属性始终处于最高优先级。如果该属性和自定义密钥格式器都存在，则将使用AliasAs属性的值。

使用UrlDataberFormatter验证URL参数值
在Refit中，RefitSettings中的UrlParameterFormatter属性允许您自定义如何在URL中设置参数值的格式。当您需要以符合API预期的特定方式格式化日期、数字或其他类型时，这可能特别有用。

使用UrlMechanterFormatter：

将实现IUrlDataberFormatter接口的自定义格式器分配给UrlDataberFormatter属性。

public class CustomDateUrlParameterFormatter : IUrlParameterFormatter
{
    public string? Format(object? value, ICustomAttributeProvider attributeProvider, Type type)
    {
        if (value is DateTime dt)
        {
            return dt.ToString("yyyyMMdd");
        }

        return value?.ToString();
    }
}

var settings = new RefitSettings
{
    UrlParameterFormatter = new CustomDateUrlParameterFormatter()
};
在此示例中，为日期值创建了自定义格式器。每当遇到DateTime参数时，它都会将日期格式化为yyyyMMdd。

收件箱字典键：

在处理字典时，重要的是要注意键被视为值。如果您需要自定义字典键格式，则也应该使用UrlMechanterFormatter。

例如，如果您有一个字典参数并且想要以特定方式格式化其键，则可以在自定义格式器中处理该参数：

public class CustomDictionaryKeyFormatter : IUrlParameterFormatter
{
    public string? Format(object? value, ICustomAttributeProvider attributeProvider, Type type)
    {
        // Handle dictionary keys
        if (attributeProvider is PropertyInfo prop && prop.PropertyType.IsGenericType && prop.PropertyType.GetGenericTypeDefinition() == typeof(Dictionary<,>))
        {
            // Custom formatting logic for dictionary keys
            return value?.ToString().ToUpperInvariant();
        }

        return value?.ToString();
    }
}

var settings = new RefitSettings
{
    UrlParameterFormatter = new CustomDictionaryKeyFormatter()
};
在上面的例子中，字典键将转换为MIDI。

正文内容
通过使用Body属性，方法中的一个参数可以用作body：

[Post("/users/new")]
Task CreateUser([Body] User user);
根据参数的类型，有四种可能性提供身体数据：

如果类型为Stream，则内容将通过StreamContent进行流式传输
如果类型为字符串，则该字符串将直接用作内容，除非设置了[Body（BodySerializationMethod.Json）]，从而将其作为StringContent发送
如果参数具有属性[Body（BodySerializationMethod.UrlEncoded）]，则内容将进行URL编码（请参阅下面的表单帖子）
对于所有其他类型，对象将使用RefitSet中指定的内容序列化程序进行序列化（默认为JNON）。
缓冲和内容长度标题
默认情况下，Refit会流式传输正文内容，而不对其进行缓冲。这意味着您可以从磁盘流式传输文件，而不会产生将整个文件加载到内存中的负担。其缺点是请求上没有设置Content-Size标头。如果您的API需要您随请求一起发送Content-Size标头，您可以通过将[Body]属性的缓冲参数设置为true来禁用此流媒体行为：

Task CreateUser([Body(buffered: true)] User user);
json内容
使用IhttpContentSerializer接口的实例来序列化/反序列化SON请求和响应。Refit提供了两种开箱即用的实现：SystemTextJsonContentSerializer（默认的SON序列化器）和NewtonsoftJsonContentSerializer。第一种使用System.Text.Json API，专注于高性能和低内存使用，而后者使用已知的Newtonsoft.Json库，功能更加通用和可定制。您可以在此链接中了解有关这两种序列化器以及两者之间主要差异的更多信息。

例如，以下是如何使用基于Newtonsoft. Json的序列化器创建新的RefitSet实例（您还需要向Refit.Newtonsoft.Json添加PackageReference）：

var settings = new RefitSettings(new NewtonsoftJsonContentSerializer());
如果您正在使用Newtonsoft.Json API，则可以通过设置Newtonsoft.Json.JsonConvert. Protect设置属性来自定义它们的行为：

JsonConvert.DefaultSettings =
    () => new JsonSerializerSettings() {
        ContractResolver = new CamelCasePropertyNamesContractResolver(),
        Converters = {new StringEnumConverter()}
    };

// Serialized as: {"day":"Saturday"}
await PostSomeStuff(new { Day = DayOfWeek.Saturday });
由于这些是全局设置，因此它们将影响您的整个应用程序。隔离对特定API的调用的设置可能是有益的。创建Refit生成的实时界面时，您可以选择传递RefitSet，该设置允许您指定想要的序列化器设置。这允许您为不同的API拥有不同的序列化程序设置：

var gitHubApi = RestService.For<IGitHubApi>("https://api.github.com",
    new RefitSettings {
        ContentSerializer = new NewtonsoftJsonContentSerializer(
            new JsonSerializerSettings {
                ContractResolver = new SnakeCasePropertyNamesContractResolver()
        }
    )});

var otherApi = RestService.For<IOtherApi>("https://api.example.com",
    new RefitSettings {
        ContentSerializer = new NewtonsoftJsonContentSerializer(
            new JsonSerializerSettings {
                ContractResolver = new CamelCasePropertyNamesContractResolver()
        }
    )});
可以使用Json.NET的JsonProperty属性自定义属性序列化/反序列化：

public class Foo
{
    // Works like [AliasAs("b")] would in form posts (see below)
    [JsonProperty(PropertyName="b")]
    public string Bar { get; set; }
}
SON源生成器
要应用.NET 6中添加的System.Text.Json的新SON源生成器的好处，您可以将SystemTextJsonContentSerializer与RefitSet和JsonSerializer的自定义实例一起使用：

var gitHubApi = RestService.For<IGitHubApi>("https://api.github.com",
    new RefitSettings {
        ContentSerializer = new SystemTextJsonContentSerializer(MyJsonSerializerContext.Default.Options)
    });
XML内容
XML请求和响应使用System. Xml. Serialization. XmlSerializer进行序列化/非序列化。默认情况下，Refit将使用JSON内容序列化，要使用XML内容，请配置ContentSerializer以使用XmlContentSerializer：

var gitHubApi = RestService.For<IXmlApi>("https://www.w3.org/XML",
    new RefitSettings {
        ContentSerializer = new XmlContentSerializer()
    });
可以使用System.Xml.Serialization命名空间中的属性来自定义属性序列化/非序列化：

    public class Foo
    {
        [XmlElement(Namespace = "https://www.w3.org/XML")]
        public string Bar { get; set; }
    }
System.Xml. Serialification. DatabSerializer提供了许多序列化选项，可以通过向DatabContentSerializer构造函数提供MQContentSerializer设置来设置这些选项：

var gitHubApi = RestService.For<IXmlApi>("https://www.w3.org/XML",
    new RefitSettings {
        ContentSerializer = new XmlContentSerializer(
            new XmlContentSerializerSettings
            {
                XmlReaderWriterSettings = new XmlReaderWriterSettings()
                {
                    ReaderSettings = new XmlReaderSettings
                    {
                        IgnoreWhitespace = true
                    }
                }
            }
        )
    });
表格职位
对于采用表单帖子的API（即序列化为应用程序/x-www-form-urlencoded），使用BodySerializationMethod. UrlEncoded初始化Body属性。

该参数可以是IDictionary：

public interface IMeasurementProtocolApi
{
    [Post("/collect")]
    Task Collect([Body(BodySerializationMethod.UrlEncoded)] Dictionary<string, object> data);
}

var data = new Dictionary<string, object> {
    {"v", 1},
    {"tid", "UA-1234-5"},
    {"cid", new Guid("d1e9ea6b-2e8b-4699-93e0-0bcbd26c206c")},
    {"t", "event"},
};

// Serialized as: v=1&tid=UA-1234-5&cid=d1e9ea6b-2e8b-4699-93e0-0bcbd26c206c&t=event
await api.Collect(data);
或者您可以只传递任何对象，所有公共、可读的属性都将被序列化为请求中的表单字段。这种方法允许您使用[AliasAs（“whatever”）]对属性名称进行别名，如果API具有神秘的字段名称，这可能会有所帮助：

public interface IMeasurementProtocolApi
{
    [Post("/collect")]
    Task Collect([Body(BodySerializationMethod.UrlEncoded)] Measurement measurement);
}

public class Measurement
{
    // Properties can be read-only and [AliasAs] isn't required
    public int v { get { return 1; } }

    [AliasAs("tid")]
    public string WebPropertyId { get; set; }

    [AliasAs("cid")]
    public Guid ClientId { get; set; }

    [AliasAs("t")]
    public string Type { get; set; }

    public object IgnoreMe { private get; set; }
}

var measurement = new Measurement {
    WebPropertyId = "UA-1234-5",
    ClientId = new Guid("d1e9ea6b-2e8b-4699-93e0-0bcbd26c206c"),
    Type = "event"
};

// Serialized as: v=1&tid=UA-1234-5&cid=d1e9ea6b-2e8b-4699-93e0-0bcbd26c206c&t=event
await api.Collect(measurement);
如果您的类型具有设置属性别名的[JsonProperty（PropertyName）]属性，则Refit也将使用这些属性别名（如果您同时具有这两个属性，[AliasAs]将优先）。这意味着以下类型将序列化为one= value 1 & two = value 2：

public class SomeObject
{
    [JsonProperty(PropertyName = "one")]
    public string FirstProperty { get; set; }

    [JsonProperty(PropertyName = "notTwo")]
    [AliasAs("two")]
    public string SecondProperty { get; set; }
}
注意：AliasAs的这种使用适用于查询字符串参数和表单正文帖子，但不适用于响应对象;对于响应对象上的别名字段，您仍然需要使用[JsonProperty（“full-Property-Name”）]。

设置请求标头
静态标题
您可以为将Headers属性应用于方法的请求设置一个或多个静态请求标头：

[Headers("User-Agent: Awesome Octocat App")]
[Get("/users/{user}")]
Task<User> GetUser(string user);
通过将Headers属性应用于接口，还可以将静态头添加到API中的每个请求：

[Headers("User-Agent: Awesome Octocat App")]
public interface IGitHubApi
{
    [Get("/users/{user}")]
    Task<User> GetUser(string user);

    [Post("/users/new")]
    Task CreateUser([Body] User user);
}
动态标题
如果需要在运行时设置标头的内容，您可以通过将标头属性应用到参数来将具有动态值的标头添加到请求中：

[Get("/users/{user}")]
Task<User> GetUser(string user, [Header("Authorization")] string authorization);

// Will add the header "Authorization: token OAUTH-TOKEN" to the request
var user = await GetUser("octocat", "token OAUTH-TOKEN");
添加授权标头是一种常见的用例，您可以通过将授权属性应用于参数并可选地指定方案来向请求添加访问令牌：

[Get("/users/{user}")]
Task<User> GetUser(string user, [Authorize("Bearer")] string token);

// Will add the header "Authorization: Bearer OAUTH-TOKEN}" to the request
var user = await GetUser("octocat", "OAUTH-TOKEN");

//note: the scheme defaults to Bearer if none provided
如果您需要在运行时设置多个标头，您可以添加IDictionary<list，list>并将HeaderCollection属性应用于参数，它会将标头注入到请求中：

[Get("/users/{user}")]
Task<User> GetUser(string user, [HeaderCollection] IDictionary<string, string> headers);

var headers = new Dictionary<string, string> {{"Authorization","Bearer tokenGoesHere"}, {"X-Tenant-Id","123"}};
var user = await GetUser("octocat", headers);
持票人身份验证
大多数API需要某种身份验证。最常见的是OAuth Bearer身份验证。将一个标头添加到格式为：授权：Bearer的每个请求中<token>。通过改装，您可以轻松地插入逻辑以根据应用程序需要获取令牌，因此您不必将令牌传递到每个方法中。

将[Headers（“Author：Bearer”）添加到需要令牌的接口或方法中。
在RefitSet实例中设置AuthationHeaderValueGetter。每次需要获取令牌时，Refit都会调用您的委托，因此您的机制在令牌生命周期内的一段时间内缓存令牌值是个好主意。
使用DelegatingHandlers减少标头样板（授权标头工作示例）
尽管我们在Refit中规定在运行时直接添加动态标头，但大多数用例可能会受益于注册自定义DelegatingButtons，以便将标头作为httpClient中间件管道的一部分注入，从而无需添加大量[Header]或[HeaderCollection]属性。

在上面的例子中，我们利用[HeaderCollection]参数来注入授权和X-Tenant-Id标头。如果您正在与使用OAuth2的第三方集成，这是一种非常常见的情况。虽然对于偶尔的端点来说这是可以的，但如果我们必须将该模板添加到界面中的每个方法中，那将是相当麻烦的。

在本例中，我们假设我们的应用程序是一个多租户应用程序，它能够通过某个接口ITenantprovider提取有关租户的信息，并且具有一个数据存储IOAuthTokenStore，可用于检索授权令牌以附加到呼出请求。

 //Custom delegating handler for adding Auth headers to outbound requests
 class AuthHeaderHandler : DelegatingHandler
 {
     private readonly ITenantProvider tenantProvider;
     private readonly IAuthTokenStore authTokenStore;

    public AuthHeaderHandler(ITenantProvider tenantProvider, IAuthTokenStore authTokenStore)
    {
         this.tenantProvider = tenantProvider ?? throw new ArgumentNullException(nameof(tenantProvider));
         this.authTokenStore = authTokenStore ?? throw new ArgumentNullException(nameof(authTokenStore));
         // InnerHandler must be left as null when using DI, but must be assigned a value when
         // using RestService.For<IMyApi>
         // InnerHandler = new HttpClientHandler();
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await authTokenStore.GetToken();

        //potentially refresh token here if it has expired etc.

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Add("X-Tenant-Id", tenantProvider.GetTenantId());

        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}

//Startup.cs
public void ConfigureServices(IServiceCollection services)
{
    services.AddTransient<ITenantProvider, TenantProvider>();
    services.AddTransient<IAuthTokenStore, AuthTokenStore>();
    services.AddTransient<AuthHeaderHandler>();

    //this will add our refit api implementation with an HttpClient
    //that is configured to add auth headers to all requests

    //note: AddRefitClient<T> requires a reference to Refit.HttpClientFactory
    //note: the order of delegating handlers is important and they run in the order they are added!

    services.AddRefitClient<ISomeThirdPartyApi>()
        .ConfigureHttpClient(c => c.BaseAddress = new Uri("https://api.example.com"))
        .AddHttpMessageHandler<AuthHeaderHandler>();
        //you could add Polly here to handle HTTP 429 / HTTP 503 etc
}

//Your application code
public class SomeImportantBusinessLogic
{
    private ISomeThirdPartyApi thirdPartyApi;

    public SomeImportantBusinessLogic(ISomeThirdPartyApi thirdPartyApi)
    {
        this.thirdPartyApi = thirdPartyApi;
    }

    public async Task DoStuffWithUser(string username)
    {
        var user = await thirdPartyApi.GetUser(username);
        //do your thing
    }
}
如果你没有使用依赖注入，那么你可以通过这样做来实现同样的事情：

var api = RestService.For<ISomeThirdPartyApi>(new HttpClient(new AuthHeaderHandler(tenantProvider, authTokenStore))
    {
        BaseAddress = new Uri("https://api.example.com")
    }
);

var user = await thirdPartyApi.GetUser(username);
//do your thing
重新定义标题
与Retrofit不同，在Retrofit中，标头不会相互覆盖，并且无论定义了多少次相同的标头，都会全部添加到请求中，而Refit采用的方法与ASP.NET MVP对操作过滤器采取的方法类似-重新定义标头将替换它，按以下优先顺序：

界面上的标题属性（最低优先级）
方法上的标头属性
方法参数上的Header属性或HeaderCollection属性（最高优先级）
[Headers("X-Emoji: :rocket:")]
public interface IGitHubApi
{
    [Get("/users/list")]
    Task<List> GetUsers();

    [Get("/users/{user}")]
    [Headers("X-Emoji: :smile_cat:")]
    Task<User> GetUser(string user);

    [Post("/users/new")]
    [Headers("X-Emoji: :metal:")]
    Task CreateUser([Body] User user, [Header("X-Emoji")] string emoji);
}

// X-Emoji: :rocket:
var users = await GetUsers();

// X-Emoji: :smile_cat:
var user = await GetUser("octocat");

// X-Emoji: :trollface:
await CreateUser(user, ":trollface:");
注意：这种重新定义行为仅适用于具有相同名称的标头。具有不同名称的标题不会被替换。以下代码将导致所有标头都被包含：

[Headers("Header-A: 1")]
public interface ISomeApi
{
    [Headers("Header-B: 2")]
    [Post("/post")]
    Task PostTheThing([Header("Header-C")] int c);
}

// Header-A: 1
// Header-B: 2
// Header-C: 3
var user = await api.PostTheThing(3);
移除页眉
在接口或方法上定义的头可以通过重定义一个没有值的静态头（即没有：<value>）或为动态头传递null来删除。空字符串将作为空标题包含在内。

[Headers("X-Emoji: :rocket:")]
public interface IGitHubApi
{
    [Get("/users/list")]
    [Headers("X-Emoji")] // Remove the X-Emoji header
    Task<List> GetUsers();

    [Get("/users/{user}")]
    [Headers("X-Emoji:")] // Redefine the X-Emoji header as empty
    Task<User> GetUser(string user);

    [Post("/users/new")]
    Task CreateUser([Body] User user, [Header("X-Emoji")] string emoji);
}

// No X-Emoji header
var users = await GetUsers();

// X-Emoji:
var user = await GetUser("octocat");

// No X-Emoji header
await CreateUser(user, null);

// X-Emoji:
await CreateUser(user, "");
将状态传递到委托处理程序
如果需要将运行时状态传递给DelegatingButtons，您可以通过将Property属性应用于参数，将具有动态值的属性添加到基础的httpReportMessage. Properties：

public interface IGitHubApi
{
    [Post("/users/new")]
    Task CreateUser([Body] User user, [Property("SomeKey")] string someValue);

    [Post("/users/new")]
    Task CreateUser([Body] User user, [Property] string someOtherKey);
}
属性构造函数可以选择接受一个字符串，该字符串成为httpDelivestMessage. Properties字典中的键。如果没有显式定义键，则参数的名称将成为键。如果某个键被定义多次，则httpDelivestMessage. Properties中的值将被覆盖。参数本身可以是任何对象。可以在委托收件箱中访问属性，如下所示：

class RequestPropertyHandler : DelegatingHandler
{
    public RequestPropertyHandler(HttpMessageHandler innerHandler = null) : base(innerHandler ?? new HttpClientHandler()) {}

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // See if the request has a the property
        if(request.Properties.ContainsKey("SomeKey"))
        {
            var someProperty = request.Properties["SomeKey"];
            //do stuff
        }

        if(request.Properties.ContainsKey("someOtherKey"))
        {
            var someOtherProperty = request.Properties["someOtherKey"];
            //do stuff
        }

        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
注：在.NET 5中，httpReportMessage. Properties已标记为Obstival，Refit将将该值填充到新的httpReportMessage. Options中。

对波莉和波莉的支持。上下文
由于Refit支持httpClientFactory，因此可以在您的httpClient上配置Polly策略。如果您的策略使用Polly.Context，可以通过Refit通过添加[Property（“Policy ExecutionContent”）] Polly.Context来传递，作为幕后Polly.Context简单地存储在httpDelivestMessage. Properties中Policy ExecutionContent下，并且类型为Polly.Context。如果您的用例要求使用仅在运行时已知的动态内容初始化Polly.上下文，则建议以这种方式传递Polly.Context。如果您的Polly.Context每次只需要相同的内容（例如您想要使用的ILogger从策略内部记录），则更干净的方法是通过DelegatingButtons注入Polly.Context，如#801所述

目标接口类型和方法信息
有时您可能想知道Refit实例的目标界面类型是什么。一个例子是，您有一个实现这样公共库的派生接口：

public interface IGetAPI<TEntity>
{
    [Get("/{key}")]
    Task<TEntity> Get(long key);
}

public interface IUsersAPI : IGetAPI<User>
{
}

public interface IOrdersAPI : IGetAPI<Order>
{
}
您可以访问接口的具体类型以在处理程序中使用，例如更改请求的URL：

class RequestPropertyHandler : DelegatingHandler
{
    public RequestPropertyHandler(HttpMessageHandler innerHandler = null) : base(innerHandler ?? new HttpClientHandler()) {}

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Get the type of the target interface
        Type interfaceType = (Type)request.Properties[HttpMessageRequestOptions.InterfaceType];

        var builder = new UriBuilder(request.RequestUri);
        // Alter the Path in some way based on the interface or an attribute on it
        builder.Path = $"/{interfaceType.Name}{builder.Path}";
        // Set the new Uri on the outgoing message
        request.RequestUri = builder.Uri;

        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
完整的方法信息（RestMethodInfo）也总是在请求选项中可用。RestMethodInfo包含有关正在调用的方法的更多信息，例如需要使用反射时的完整MethodInfo：

class RequestPropertyHandler : DelegatingHandler
{
    public RequestPropertyHandler(HttpMessageHandler innerHandler = null) : base(innerHandler ?? new HttpClientHandler()) {}

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Get the method info
        if (request.Options.TryGetValue(HttpRequestMessageOptions.RestMethodInfoKey, out RestMethodInfo restMethodInfo))
        {
            var builder = new UriBuilder(request.RequestUri);
            // Alter the Path in some way based on the method info or an attribute on it
            builder.Path = $"/{restMethodInfo.MethodInfo.Name}{builder.Path}";
            // Set the new Uri on the outgoing message
            request.RequestUri = builder.Uri;
        }

        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
注：在.NET 5中，httpReportMessage. Properties已标记为Obstival，Refit将将该值填充到新的httpReportMessage. Options中。Refit提供了httpReportMessage选项. InterfaceTypKey和httpReportMessage选项.RestMethodInfoKey，以分别从选项中访问接口类型和REST方法信息。

Multipart uploads
用多部分属性装饰的方法将与多部分内容类型一起提交。目前，多部分方法支持以下参数类型：

字符串（参数名称将用作名称，字符串值用作值）
字节数组
流
FileInfo
多部分数据优先级中的字段名称：

MultiPartProject.Name（如果指定且不为空）;动态，允许在执行时命名表单数据部分。
[AliasAs]属性（可选），装饰方法签名中的streamPart参数（见下文）;静态，在代码中定义。
MultiPartProject参数名称（默认），如方法签名中定义的;静态，在代码中定义。
可以通过Multichar属性的可选字符串参数指定自定义边界。如果留空，默认为-MyGreatBoundary。

要指定字节数组（byte[]）、Stream和FilInfo参数的文件名和内容类型，需要使用包装器类。这些类型的包装类是ByteArrayPart、StreamPart和FilInfoPart。

public interface ISomeApi
{
    [Multipart]
    [Post("/users/{id}/photo")]
    Task UploadPhoto(int id, [AliasAs("myPhoto")] StreamPart stream);
}
要将Stream传递给此方法，请像这样构造StreamPart对象：

someApiInstance.UploadPhoto(id, new StreamPart(myPhotoStream, "photo.jpg", "image/jpeg"));
注意：本节之前描述的AttachmentName属性已被弃用，不建议使用。

检索响应
请注意，与Retrofit不同，在Refit中没有同步网络请求选项-所有请求都必须是Deliverc，无论是通过Task还是通过IOObservable。与Retrofit不同，也没有通过Callback参数创建Deliverc方法的选项，因为我们生活在Deliverc/wait未来。

与正文内容如何通过参数类型改变类似，返回类型将确定返回的内容。

返回不带类型参数的任务将放弃内容并仅告诉您调用是否成功：

[Post("/users/new")]
Task CreateUser([Body] User user);

// This will throw if the network call fails
await CreateUser(someUser);
如果类型参数为“httpResponseMessage”或“string”，则将分别返回原始响应消息或字符串形式的内容。

// Returns the content as a string (i.e. the JSON data)
[Get("/users/{user}")]
Task<string> GetUser(string user);

// Returns the raw response, as an IObservable that can be used with the
// Reactive Extensions
[Get("/users/{user}")]
IObservable<HttpResponseMessage> GetUser(string user);
还有一个名为ApiResponse的通用包装类<T>，可用作返回类型。使用此类作为返回类型不仅可以检索作为对象的内容，还可以检索与请求/响应相关的任何元数据。这包括响应标头、http状态代码和原因短语（例如404 Not Found）、响应版本、发送的原始请求消息以及在发生错误的情况下包含错误详细信息的ApiResponse对象等信息。以下是如何检索响应元数据的一些示例。

//Returns the content within a wrapper class containing metadata about the request/response
[Get("/users/{user}")]
Task<ApiResponse<User>> GetUser(string user);

//Calling the API
var response = await gitHubApi.GetUser("octocat");

//Getting the status code (returns a value from the System.Net.HttpStatusCode enumeration)
var httpStatus = response.StatusCode;

//Determining if a success status code was received and there wasn't any other error
//(for example, during content deserialization)
if(response.IsSuccessful)
{
    //YAY! Do the thing...
}

//Retrieving a well-known header value (e.g. "Server" header)
var serverHeaderValue = response.Headers.Server != null ? response.Headers.Server.ToString() : string.Empty;

//Retrieving a custom header value
var customHeaderValue = string.Join(',', response.Headers.GetValues("A-Custom-Header"));

//Looping through all the headers
foreach(var header in response.Headers)
{
    var headerName = header.Key;
    var headerValue = string.Join(',', header.Value);
}

//Finally, retrieving the content in the response body as a strongly-typed object
var user = response.Content;
使用泛型接口
当使用诸如ASP.NET Web API之类的东西时，拥有整个CRUD REST服务堆栈是一种相当常见的模式。Refit现在支持这些，允许您定义具有通用类型的单个API接口：

public interface IReallyExcitingCrudApi<T, in TKey> where T : class
{
    [Post("")]
    Task<T> Create([Body] T payload);

    [Get("")]
    Task<List<T>> ReadAll();

    [Get("/{key}")]
    Task<T> ReadOne(TKey key);

    [Put("/{key}")]
    Task Update(TKey key, [Body]T payload);

    [Delete("/{key}")]
    Task Delete(TKey key);
}
可以这样使用：

// The "/users" part here is kind of important if you want it to work for more
// than one type (unless you have a different domain for each type)
var api = RestService.For<IReallyExcitingCrudApi<User, string>>("http://api.example.com/users");
接口继承
当需要分开的多个服务共享多个API时，可以利用接口继承来避免必须在不同服务中多次定义相同的Refit方法：

public interface IBaseService
{
    [Get("/resources")]
    Task<Resource> GetResource(string id);
}

public interface IDerivedServiceA : IBaseService
{
    [Delete("/resources")]
    Task DeleteResource(string id);
}

public interface IDerivedServiceB : IBaseService
{
    [Post("/resources")]
    Task<string> AddResource([Body] Resource resource);
}
在此示例中，IDeriivedServiceA接口将公开GetResource和DeleteResource API，而IDeriivedServiceB将公开GetResource和AddResource。

标题继承
当使用继承时，现有的header属性也将被传递，最里面的属性将具有优先级：

[Headers("User-Agent: AAA")]
public interface IAmInterfaceA
{
    [Get("/get?result=Ping")]
    Task<string> Ping();
}

[Headers("User-Agent: BBB")]
public interface IAmInterfaceB : IAmInterfaceA
{
    [Get("/get?result=Pang")]
    [Headers("User-Agent: PANG")]
    Task<string> Pang();

    [Get("/get?result=Foo")]
    Task<string> Foo();
}
在这里，IAmInterfaceB.Pang（）将使用PANG作为其用户代理，而IAmInterfaceB.Foo和IAmInterfaceB.Ping将使用BBB。请注意，如果IAmInterfaceB没有标头属性，则Foo将使用从IAmInterfaceA继承的AAA值。如果接口继承多个接口，则优先顺序与声明继承接口的顺序相同：

public interface IAmInterfaceC : IAmInterfaceA, IAmInterfaceB
{
    [Get("/get?result=Foo")]
    Task<string> Foo();
}
在这里，IAmInterfaceC.Foo将使用从IAmInterfaceA继承的头属性（如果存在），或者从IAmInterfaceB继承的头属性，以此类推。

默认接口方法
从C#8.0开始，默认接口方法（又名DIM）可以在接口上定义。改装接口可以使用DIM提供额外逻辑，可选地与私有和/或静态助手方法结合：

public interface IApiClient
{
    // implemented by Refit but not exposed publicly
    [Get("/get")]
    internal Task<string> GetInternal();
    // Publicly available with added logic applied to the result from the API call
    public async Task<string> Get()
        => FormatResponse(await GetInternal());
    private static String FormatResponse(string response)
        => $"The response is: {response}";
}
Refit生成的类型将实现IApiClient.GetInternal方法。如果在其调用之前或之后需要额外的逻辑，则不应该直接公开它，因此可以通过标记为内部来对消费者隐藏它。默认接口方法IApiClient.Get将被实现IApiClient的所有类型继承，当然也包括由Refit生成的类型。IApiClient的消费者将调用公共Get方法，并从其实现中提供的附加逻辑中获益（可选地，在本例中，在私有静态帮助器RESPONSE Response的帮助下）。要支持不支持DIM的运行时（.NET Core 2.x及更低版本或.NET Standard 2.0及更低版本），同一解决方案需要两种额外类型。

internal interface IApiClientInternal
{
    [Get("/get")]
    Task<string> Get();
}
public interface IApiClient
{
    public Task<string> Get();
}
internal class ApiClient : IApiClient
{
    private readonly IApiClientInternal client;
    public ApiClient(IApiClientInternal client) => this.client = client;
    public async Task<string> Get()
        => FormatResponse(await client.Get());
    private static String FormatResponse(string response)
        => $"The response is: {response}";
}
使用httpClientFactory
Refit对ASP.NET Core 2.1 httpClientFactory提供一流的支持。添加对Refit.httpClientFactory的引用，并在您的IntegrureServices方法中调用提供的扩展方法来配置您的Refit界面：

services.AddRefitClient<IWebApi>()
        .ConfigureHttpClient(c => c.BaseAddress = new Uri("https://api.example.com"));
        // Add additional IHttpClientBuilder chained methods as required here:
        // .AddHttpMessageHandler<MyHandler>()
        // .SetHandlerLifetime(TimeSpan.FromMinutes(2));
也可以包含RefitSettings对象：

var settings = new RefitSettings();
// Configure refit settings here

services.AddRefitClient<IWebApi>(settings)
        .ConfigureHttpClient(c => c.BaseAddress = new Uri("https://api.example.com"));
        // Add additional IHttpClientBuilder chained methods as required here:
        // .AddHttpMessageHandler<MyHandler>()
        // .SetHandlerLifetime(TimeSpan.FromMinutes(2));

// or injected from the container
services.AddRefitClient<IWebApi>(provider => new RefitSettings() { /* configure settings */ })
        .ConfigureHttpClient(c => c.BaseAddress = new Uri("https://api.example.com"));
        // Add additional IHttpClientBuilder chained methods as required here:
        // .AddHttpMessageHandler<MyHandler>()
        // .SetHandlerLifetime(TimeSpan.FromMinutes(2));
请注意，RefitSettings的某些属性将被忽略，因为HttpClient和HttpClientHandlers将由HttpClientFactory而不是Refit管理。

然后你可以使用构造函数注入来获取api接口：

public class HomeController : Controller
{
    public HomeController(IWebApi webApi)
    {
        _webApi = webApi;
    }

    private readonly IWebApi _webApi;

    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        var thing = await _webApi.GetSomethingWeNeed(cancellationToken);
        return View(thing);
    }
}
提供自定义的httpClient
您可以通过简单地将其作为参数传递给RestService.For方法来提供自定义HttpClient实例<T>：

RestService.For<ISomeApi>(new HttpClient()
{
    BaseAddress = new Uri("https://www.someapi.com/api/")
});
但是，当提供自定义HttpClient实例时，以下RefitSettings属性将不起作用：

AuthorizationHeaderValueGetter
https Message HandlerFactory
如果您仍然希望能够配置Refit提供的htttpClient实例，同时仍然使用上述设置，只需在API接口上公开htttpClient即可：

interface ISomeApi
{
    // This will automagically be populated by Refit if the property exists
    HttpClient Client { get; }

    [Headers("Authorization: Bearer")]
    [Get("/endpoint")]
    Task<string> SomeApiEndpoint();
}
然后，创建REST服务后，您可以设置任何您想要的httpClient属性，例如：

SomeApi = RestService.For<ISomeApi>("https://www.someapi.com/api/", new RefitSettings()
{
    AuthorizationHeaderValueGetter = (rq, ct) => GetTokenAsync()
});

SomeApi.Client.Timeout = timeout;
处理异常
Refit具有不同的异常处理行为，具体取决于您的Refit接口方法是否返回<T>Task、<IApiResponse>Task&lt;IapiResponse<T>&gt;或Task&lt;ApiResponse<T>&gt;。

返回Task<IApiResponse>、Task &amp; IapiResponse <T>&amp;或Task &amp; ApiResponse <T>&amp;时
Refit捕获处理响应时由ExceptionFactory引发的任何ApiException，以及尝试将响应转换为ApiResponse时发生的任何错误<T>，并将异常填充到ApiResponse的Error属性中，而<T>不引发异常。

然后你可以决定怎么做，就像这样：

var response = await _myRefitClient.GetSomeStuff();
if(response.IsSuccessful)
{
   //do your thing
}
else
{
   _logger.LogError(response.Error, response.Error.Content);
}
注意

IsSuccessful属性检查响应状态代码是否在200-299范围内并且没有任何其他错误（例如，在内容反序列化期间）。如果您只是想检查HTTP响应状态代码，则可以使用Isloe StatusCode属性。

返回任务时<T>
Refit会在处理响应时引发ExceptionFactory引发的任何Api异常以及尝试重新序列化对任务的响应时出现的任何错误<T>。

// ...
try
{
   var result = await awesomeApi.GetFooAsync("bar");
}
catch (ApiException exception)
{
   //exception handling
}
// ...
当服务实现问题详细信息的RFC 7807规范并且响应内容类型为app/problem+json时，Refit还可以抛出ValidationApiResponse，除了ApiResponse上存在的信息外，它还包含ProblemDetails

有关验证异常问题详细信息的具体信息，只需捕获GuardationApiResponse：

// ...
try
{
   var result = await awesomeApi.GetFooAsync("bar");
}
catch (ValidationApiException validationException)
{
   // handle validation here by using validationException.Content,
   // which is type of ProblemDetails according to RFC 7807

   // If the response contains additional properties on the problem details,
   // they will be added to the validationException.Content.Extensions collection.
}
catch (ApiException exception)
{
   // other exception handling
}
// ...
提供自定义ExceptionFactory
您还可以通过在RefitSet中提供自定义异常工厂来覆盖处理结果时ExceptionFactory引发的默认异常行为。例如，您可以通过以下操作抑制所有异常：

var nullTask = Task.FromResult<Exception>(null);

var gitHubApi = RestService.For<IGitHubApi>("https://api.github.com",
    new RefitSettings {
        ExceptionFactory = httpResponse => nullTask;
    });
对于尝试反序列化响应时出现的异常，请使用下文所述的ReconializationExceptionFactory。

提供自定义虚拟化ExceptionFactory
您可以通过在RefitSet中提供自定义异常工厂来覆盖在处理结果时由ParticializationExceptionFactory引发的默认反序列化异常行为。例如，您可以使用以下内容抑制所有反序列化异常：

var nullTask = Task.FromResult<Exception>(null);

var gitHubApi = RestService.For<IGitHubApi>("https://api.github.com",
    new RefitSettings {
        DeserializationExceptionFactory = (httpResponse, exception) => nullTask;
    });
用Serilog解构ApiExcept
对于Serilog的用户，您可以使用Serilog..Refit NuGet包丰富ApiDoc的日志记录。有关如何将此包集成到您的应用程序中的详细信息，请在此处找到。