using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using RefitDemo.Common.Models;
using RefitDemo.Common.Services;

namespace RefitDemo
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            this.Loaded += MainWindow_Loaded;
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // 创建API客户端
            var api = ApiClientFactory.Create<IJsonPlaceholderApi>("https://jsonplaceholder.typicode.com");

            // 示例1: 获取所有帖子
            Console.WriteLine("获取所有帖子...");
            try
            {
                var posts = await api.GetPostsAsync();
                Console.WriteLine($"获取到 {posts.Count} 个帖子\n");
                postList.ItemsSource = posts;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            // 示例2: 获取单个帖子
            Console.WriteLine("获取单个帖子 (ID=1)...");
            var post = await api.GetPostAsync(1);
            Console.WriteLine($"帖子标题: {post.Title}\n");

            // 示例3: 创建新帖子
            Console.WriteLine("创建新帖子...");
            var newPost = new Post
            {
                UserId = 1,
                Title = "Refit Demo Post",
                Body = "This is a test post created using Refit"
            };
            var createdPost = await api.CreatePostAsync(newPost);
            Console.WriteLine($"创建成功! 新帖子ID: {createdPost.Id}, 标题: {createdPost.Title}\n");

            // 示例4: 更新帖子
            Console.WriteLine("更新帖子 (ID=1)...");
            var postToUpdate = await api.GetPostAsync(1);
            postToUpdate.Title = "Updated Title";
            var updatedPost = await api.UpdatePostAsync(1, postToUpdate);
            Console.WriteLine($"更新成功! 新标题: {updatedPost.Title}\n");

            // 示例5: 删除帖子
            Console.WriteLine("删除帖子 (ID=1)...");
            await api.DeletePostAsync(1);
            Console.WriteLine("删除成功! (模拟删除)\n");

            // 示例6: 获取用户信息
            Console.WriteLine("获取用户信息 (ID=1)...");
            var user = await api.GetUserAsync(1);
            Console.WriteLine($"用户信息: {user}\n");
        }
    }
}
