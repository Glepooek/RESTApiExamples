using Refit;
using RefitDemo.Common.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace RefitDemo.Common.Services
{
    public interface IJsonPlaceholderApi
    {
        /// <summary>
        /// 获取所有帖子
        /// </summary>
        /// <returns></returns>
        [Get("/posts")]
        Task<List<Post>> GetPostsAsync();

        /// <summary>
        /// 获取单个帖子
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [Get("/posts/{id}")]
        Task<Post> GetPostAsync(int id);

        /// <summary>
        /// 创建新帖子
        /// </summary>
        /// <param name="post"></param>
        /// <returns></returns>
        [Post("/posts")]
        Task<Post> CreatePostAsync([Body] Post post);

        /// <summary>
        /// 更新帖子
        /// </summary>
        /// <param name="id"></param>
        /// <param name="post"></param>
        /// <returns></returns>
        [Put("/posts/{id}")]
        Task<Post> UpdatePostAsync(int id, [Body] Post post);

        /// <summary>
        /// 删除帖子
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [Delete("/posts/{id}")]
        Task DeletePostAsync(int id);

        /// <summary>
        /// 获取用户信息
        /// </summary>
        /// <returns></returns>
        [Get("/users")]
        Task<List<User>> GetUsersAsync();

        /// <summary>
        /// 获取特定用户信息
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [Get("/users/{id}")]
        Task<User> GetUserAsync(int id);
    }
}
