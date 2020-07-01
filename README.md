# what

Spring Security 是为基于Spring的应用程序提供声明式安全保护的安全性框架。

Spring Security提供了完整的安全性解决方案，它能够在Web请求级别和方法调用级别处理身份认证和授权。因为基于Spring框架，所以Spring Security充分利用了依赖注入和面向切面技术。





# Start


little tip

我们可以写一个控制器用于页面跳转

之前：

![](/pictureForReadme/pic1.png)

现在：

```java
@Controller
public class RouterController {
    @RequestMapping({"/","/index"})
    public String index(){
        return "index";
    }
    @RequestMapping("/toLogin")
    public String toLogin(){
        return "views/login";
    }
    @RequestMapping("/level1/{id}")
    public String toLogin1(@PathVariable("id") int id){
        return "views/level1/"+id;
    }
    @RequestMapping("/level2/{id}")
    public String toLogin2(@PathVariable("id") int id){
        return "views/level2/"+id;
    }
    @RequestMapping("/level3/{id}")
    public String toLogin3(@PathVariable("id") int id){
        return "views/level3/"+id;
    }
}

```



## 基本概念

我们仅仅需要导入spring-boot-starter-security模块，进行少量配置，就可以实现强大的安全管理



记住这几个重要的类：

- WebSecurityConfigurerAdapter: 自定义security策略
- AuthenticationManagerBuilder : 自定义认证策略
- @EnableWebSecurity: 开启Web security模式



```xml
<dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```



最简单的配置

只需要写一个类，继承WebSecurityConfigurerAdapter，然后用注解开启Web security模式

```java
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
}
```

几个重要的继承方法

| 方法                                    | 描述                                    |
| --------------------------------------- | --------------------------------------- |
| configure(WebSecurity)                  | 通过重载，配置Spring Security的Filter链 |
| configure(HttpSecurity)                 | 通过重载，配置如何通过拦截器保护请求    |
| configure(AuthenticationManagerBuilder) | 通过重载，配置user-detail服务           |



### 拦截请求：

重写configure(HttpSecurity)方法

1.用HttpSecurity对象调用authorizeRequests()，然后调用该方法所返回的对象的方法来配置请求级别的安全性细节。（设置路径）

2.设置路径：

- .antMatchers("")   支持Ant放个的通配符
- .regexMatchers("")   支持正则表达式

3.定义如何保护路径

用来定义保护路径的配置方法：

| 方法            | 用途                                 |
| --------------- | ------------------------------------ |
| permitAll()     | 允许所有用户访问                     |
| denyAll()       | 无条件拒绝所有访问                   |
| authenticated() | 允许认证过的用户访问                 |
| hasRole(String) | 如果用户具备给定角色的话，就允许访问 |
| ...             | ......                               |

配置示例

```java
protected void configure(HttpSecurity http) throws Exception {
        //首页所有人可以访问，功能页只有对应有权限的人才能访问
        http.authorizeRequests().
                antMatchers("/").permitAll().
                antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        //没有权限默认回到登录页
        http.formLogin();

    }
```

#### 防止跨站请求伪造

```java
http.csrf().disable();
```

​		（而且不写这句话登出功能会失败）

### 用户认证：

1.重写configure(AuthenticationManagerBuilder auth)方法

2.用auth建造者对象启用用户存储

- inMemoryAuthentication()   启用内存用户存储
- jdbcAuthentication()  启用以JDBC为支撑的用户存储

3.inMemoryAuthentication().withUser()方法为内存用户存储添加新的用户

withUser()返回的式UserDetailsManagerConfigurer.UserDetailsBuilder,这个对象提供了多个进一步配置用户的方法

| 方法             | 描述                                           |
| ---------------- | ---------------------------------------------- |
| password(String) | 定义用户的密码（不能直接用明文密码，需要编码） |
| roles(Stirng)    | 授予某一用户一项或多项角色                     |
| and()            | 用来连接配置                                   |



实例：

```java
 protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("fzj").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");
    }
```





### 登录 & 注销 & 记住我：

#### 登录：

1.HttpSecurity调用方法formLogin()

2.在页面表单请求地址th:action="@{/login}"

注意：

表单里的name分别为username和password是默认的

![](/pictureForReadme/pic2.png)

表单提交的地址要跟formLogin()指定的地址保持一致，默认是/login



#### 注销：

1.HttpSecurity调用方法logout()

​	http.logout();

​	http.logout().logoutSuccessUrl("/")指定登出后显示的界面

2.

```html
<a th:href="@{/logout}">退出</a>
```



#### 记住我：

```java
http.rememberMe();//默认保存两周

<input type="checkbox" name="remember-me" id="remember-me">
http.rememberMe().rememberMeParameter("remember-me");//自定义接受前端参数
```

呃，这里的remember me并不是记住账号，其实就是登陆后添加了一个cookie

只要你没有清除cookie那你就保持登录状态。

### 保护视图

1. 导包     thymeleaf 和 spring security整合包

```xml
<!-- https://mvnrepository.com/artifact/org.thymeleaf.extras/thymeleaf-extras-springsecurity4 -->
        <dependency>
            <groupId>org.thymeleaf.extras</groupId>
            <artifactId>thymeleaf-extras-springsecurity4</artifactId>
            <version>3.0.4.RELEASE</version>
        </dependency>
```

2. 引入命名空间

```html
<html lang="en" xmlns:th="http://www.thymeleaf.org" xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity4">
```

3. 使用标签

```html
<div sec:authorize="!isAuthenticated()">
    <a class="item" th:href="@{/toLogin}">
       <i class="address card icon"></i> 登录
    </a>
</div>
```



| 属性               | 作用                                                         |
| ------------------ | ------------------------------------------------------------ |
| sec:authorize      | 如果用户被授予了特定的权限或者SpEL表达式的计算结果为true，那么渲染这个标签体的内容 |
|                    | isAuthenticated()属性是一个布尔值，指示当前用户是否已通过身份验证（已登录）。 |
|                    | hasRole('')查看档期那用户是否拥有此角色                      |
| sec:authentication | 可以通过它来获取当前用户认证对象的详细信息                   |
|                    | 用户：<span sec:authentication="name"></span>                |
|                    | 角色：<span sec:authentication="principal.getAuthorities()"></span> |



可以通过

```
<div class="column" sec:authorize="hasRole('vip1')">
     <h1>1</h1>
</div>
<div class="column" sec:authorize="hasRole('vip2')">
     <h1>2</h1>
</div>
<div class="column" sec:authorize="hasRole('vip3')">
     <h1>3</h1>
</div>
```

来实现动态菜单
