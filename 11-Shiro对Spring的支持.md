TODO:【题图】

# Shiro 对 Spring 的支持

`Shiro` 的第一个版本发布于 2004 年， `Spring` 项目起源于 2002 年，在 `Shiro` 最初的版本中没有与 `Spring` 相关的内容。后来，随着 `Spring` 的流行，从 2010 年开始， `Shiro` 开始提供对 `Spring` 的支持，推出了一个独立的 jar 包，名为 `shiro-spring`。从 2018 年开始， `Shiro` 在 v1.4 中开始增强对 `SpringBoot` 的支持。

在本章中，我们先解释整合的步骤，然后再对运行机制和源码进行分析，内容结构如下：

- Shiro 与 SpringBoot 的整合步骤
- 运行机制和源码分析

## 11.1 Shiro 与 SpringBoot 的整合步骤

### 11.1.1 添加项目依赖

首先，需要在 SpringBoot 项目的 `pom.xml` 文件中添加 Shiro 的相关依赖。以下是 Maven 的依赖配置：

```xml
<dependencies>
    <!-- SpringBoot 相关的依赖，这里省略 -->

    <!-- Shiro -->
    <dependency>
        <groupId>org.apache.shiro</groupId>
        <artifactId>shiro-spring</artifactId>
        <classifier>jakarta</classifier>
        <version>${shiro.version}</version>
        <exclusions>
            <exclusion>
                <groupId>org.apache.shiro</groupId>
                <artifactId>shiro-core</artifactId>
            </exclusion>
            <exclusion>
                <groupId>org.apache.shiro</groupId>
                <artifactId>shiro-web</artifactId>
            </exclusion>
        </exclusions>
    </dependency>
    <dependency>
        <groupId>org.apache.shiro</groupId>
        <artifactId>shiro-core</artifactId>
        <classifier>jakarta</classifier>
        <version>${shiro.version}</version>
    </dependency>
    <dependency>
        <groupId>org.apache.shiro</groupId>
        <artifactId>shiro-web</artifactId>
        <classifier>jakarta</classifier>
        <version>${shiro.version}</version>
        <exclusions>
            <exclusion>
                <groupId>org.apache.shiro</groupId>
                <artifactId>shiro-core</artifactId>
            </exclusion>
        </exclusions>
    </dependency>
    <dependency>
        <groupId>org.apache.shiro</groupId>
        <artifactId>shiro-ehcache</artifactId>
        <version>${shiro.version}</version>
    </dependency>
</dependencies>
```

这是常见的 Maven 配置文件，这里不作解释。**有一个点需要注意： Shiro 的版本与 SpringBoot 的版本之间存在兼容性问题，如果读者使用了最新的 SpringBoot 版本，需要自己修改配置方式并测试兼容性。**

### 11.1.2 编写 ShiroConfig.java 文件

在 SpringBoot 中，Shiro 的配置通常通过 Java 配置类来实现。首先，需要创建一个配置类 ShiroConfig.java ：

```java
@Configuration
public class ShiroConfig {
    //...
}
```

### 11.1.3 实现自定义 Realm

`Realm` 是 Shiro 的核心组件之一，用于从数据源中获取用户的认证和授权信息。实现自定义 `Realm` 类，可以根据应用的需求从数据库或其他数据源中获取用户信息，以下是自定义 `NiceFishMySQLRealm` 示例：

```java
package com.nicefish.rbac.shiro.realm;

import com.nicefish.rbac.jpa.entity.UserEntity;
import com.nicefish.rbac.service.IUserService;
import com.nicefish.rbac.shiro.util.NiceFishSecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Set;

public class NiceFishMySQLRealm extends AuthorizingRealm {
    private static final Logger logger = LoggerFactory.getLogger(NiceFishMySQLRealm.class);

    @Autowired
    private IUserService userService;

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
        String username = usernamePasswordToken.getUsername();
        String password = usernamePasswordToken.getPassword()!=null?new String(usernamePasswordToken.getPassword()):"";

        UserEntity userEntity;
        try {
            userEntity = userService.checkUser(username, password);
            logger.debug("UserName>"+username);
            logger.debug("Password>"+password);
        }catch (Exception e) {
            logger.error(username + "登录失败{}", e.getMessage());
            throw new AuthenticationException(e.getMessage(), e);
        }

        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(userEntity, password, getName());
        return info;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        Integer userId= NiceFishSecurityUtils.getUserId();

        Set<String> permStrs=this.userService.getPermStringsByUserId(userId);
        logger.debug(permStrs.toString());

        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.setStringPermissions(permStrs);
        return info;
    }
}
```

在 ShiroConfig.java 中配置自定义的 `NiceFishMySQLRealm` ：

```java
@Bean
public NiceFishMySQLRealm nicefishRbacRealm() {
    NiceFishMySQLRealm niceFishMySQLRealm = new NiceFishMySQLRealm();
    niceFishMySQLRealm.setCachingEnabled(true);
    niceFishMySQLRealm.setAuthenticationCachingEnabled(true);
    niceFishMySQLRealm.setAuthenticationCacheName("authenticationCache");
    niceFishMySQLRealm.setAuthorizationCachingEnabled(true);
    niceFishMySQLRealm.setAuthorizationCacheName("authorizationCache");
    return niceFishMySQLRealm;
}
```

### 11.1.4 配置过滤器

在 ShiroConfig.java 中配置过滤器：

```java
@Bean
public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
    ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
    shiroFilterFactoryBean.setSecurityManager(securityManager);
    shiroFilterFactoryBean.setLoginUrl(loginUrl);
    shiroFilterFactoryBean.setUnauthorizedUrl(unauthorizedUrl);

    Map<String, Filter> filters = new LinkedHashMap<String, Filter>();
    filters.put("captchaValidateFilter", captchaValidateFilter());
    shiroFilterFactoryBean.setFilters(filters);

    //所有静态资源交给Nginx管理，这里只配置与 shiro 相关的过滤器。
    LinkedHashMap<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
    filterChainDefinitionMap.put("/nicefish/cms/post/write-post", "captchaValidateFilter");
    filterChainDefinitionMap.put("/nicefish/cms/post/update-post", "captchaValidateFilter");
    filterChainDefinitionMap.put("/nicefish/cms/comment/write-comment", "captchaValidateFilter");
    filterChainDefinitionMap.put("/nicefish/auth/user/register", "anon,captchaValidateFilter");
    filterChainDefinitionMap.put("/nicefish/auth/shiro/login", "anon,captchaValidateFilter");
    filterChainDefinitionMap.put("/**", "anon");

    shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
    return shiroFilterFactoryBean;
}
```

`ShiroFilterFactoryBean` 是 Shiro 与 Spring 集成的核心类之一，它的主要功能是把自定义的 Filter 插入到 Spring 的过滤器链中，从而拦截到符合配置项的请求，转发给 Shiro 处理。

## 11.2 运行机制和源码分析

- ShiroConfig.java 配置文件的解析与 Bean 的实例化
- Shiro 在 SpringBoot 中的启动过程
- 请求的处理过程
- Session 的处理过程
- 注解的解析过程

### 11.2.1 ShiroConfig.java 配置文件的解析与 Bean 的实例化

TODO:完成这段内容

### 11.2.2 Shiro 在 SpringBoot 中的启动过程

TODO:完成这段内容

Shiro 自己实现的 AOP 机制是如何与 Spring 整合的？

Shiro 的方法拦截器

那么， `AopAllianceAnnotationsAuthorizingMethodInterceptor` 这个类具体又做了什么事情呢？我们来看它的关键源代码：

```java
public class AopAllianceAnnotationsAuthorizingMethodInterceptor
        extends AnnotationsAuthorizingMethodInterceptor implements MethodInterceptor {

    public AopAllianceAnnotationsAuthorizingMethodInterceptor() {
        List<AuthorizingAnnotationMethodInterceptor> interceptors =
                new ArrayList<AuthorizingAnnotationMethodInterceptor>(5);

        //use a Spring-specific Annotation resolver - Spring's AnnotationUtils is nicer than the
        //raw JDK resolution process.
        AnnotationResolver resolver = new SpringAnnotationResolver();
        //we can re-use the same resolver instance - it does not retain state:

        //注意这里的拦截器， Shiro 实现了5种注解拦截器。
        interceptors.add(new RoleAnnotationMethodInterceptor(resolver));
        interceptors.add(new PermissionAnnotationMethodInterceptor(resolver));
        interceptors.add(new AuthenticatedAnnotationMethodInterceptor(resolver));
        interceptors.add(new UserAnnotationMethodInterceptor(resolver));
        interceptors.add(new GuestAnnotationMethodInterceptor(resolver));

        setMethodInterceptors(interceptors);
    }

}
```

这一组权限注解拦截器的继承结构如下：

<img src="./imgs/MethodInterceptor.png">

我们来分析 `PermissionAnnotationMethodInterceptor` 的实现，其它拦截器的实现逻辑类似，在 `PermissionAnnotationMethodInterceptor` 内部，会调用工具类 `PermissionAnnotationHandler`来负责真正的权限检测功能，其中的关键代码如下（已省略无关代码）：

```java
public class PermissionAnnotationHandler extends AuthorizingAnnotationHandler {
    //...

    public void assertAuthorized(Annotation a) throws AuthorizationException {
        if (!(a instanceof RequiresPermissions)) return;

        RequiresPermissions rpAnnotation = (RequiresPermissions) a;
        String[] perms = getAnnotationValue(a);
        Subject subject = getSubject();

        if (perms.length == 1) {
            //检查权限
            subject.checkPermission(perms[0]);
            return;
        }
        if (Logical.AND.equals(rpAnnotation.logical())) {
            //检查权限
            getSubject().checkPermissions(perms);
            return;
        }
        if (Logical.OR.equals(rpAnnotation.logical())) {
            // Avoid processing exceptions unnecessarily - "delay" throwing the exception by calling hasRole first
            boolean hasAtLeastOnePermission = false;
            for (String permission : perms) if (getSubject().isPermitted(permission)) hasAtLeastOnePermission = true;
            // Cause the exception if none of the role match, note that the exception message will be a bit misleading
            if (!hasAtLeastOnePermission) getSubject().checkPermission(perms[0]);

        }
    }
}
```

**也就是说：只要我们在某个方法加上了权限注解， Spring 在启动的时候就会自动创建代理类，然后在运行时，当这个方法被调用的时候，Shiro 中的对应的权限拦截器就会首先被执行，这就是权限注解的整体运行机制。**

那么，还有一个问题，我们自己定义的方法是什么时候被调用的呢？完整的调用轨迹是什么呢？我们在“Shiro 与 Spring 的整合”这一章中做详细的分析。

### 11.2.3 请求的处理过程

TODO: Shiro 是如何把自己的 Filter 整合到 Spring 的过滤器链中的？

### 11.2.4 Session 的处理过程

TODO:完成这段内容

### 11.2.5 注解的解析过程

权限注解是如何与 Spring 整合的？

首先， Shiro 自己实现了一套轻量级的 AOP 机制，这一套机制没有 Spring 那么复杂，也不是为了取代 Spring 。在 Shiro 的 AOP 机制中，主要有两个核心的处理流程：注解扫描、方法拦截。这样实现的目的是：

- 方便与 `Spring` 集成：当 `Spring` 启动时， `AuthorizationAttributeSourceAdvisor` 这个类会扫描所有权限注解，对于扫描到的方法， `Spring` 会生成代理对象，并将 `Shiro` 的 `MethodInterceptor` 加入到拦截器链中。当带有权限注解的方法被调用时，代理对象会先调用 `MethodInterceptor` 。在 `MethodInterceptor` 内部会通过 `SecurityManager` 调用相应的权限检查逻辑，如果检查通过，则继续执行方法，否则抛出异常。 Shiro 实现了一组类，构建了与 Spring 之间的桥梁，让 Shiro 可以把自己的处理逻辑嵌入到 Spring 的控制流中去。
- 可以脱离 Spring 框架独立运行，也可以与其它 AOP 框架集成。

我们先来看 Shiro 是如何与 Spring 配合扫描权限注解的。

在 shiro-spring-XXX-jakarta.jar 中，有一个关键的配置类 `ShiroAnnotationProcessorConfiguration` ，它是 Shiro 与 Spring 整合的关键桥梁。`ShiroAnnotationProcessorConfiguration` 的代码非常少，完整列举如下：

```java
package org.apache.shiro.spring.config;


import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

/**
 * @since 1.4.0
 */
@Configuration
public class ShiroAnnotationProcessorConfiguration extends AbstractShiroAnnotationProcessorConfiguration{

    @Bean
    @DependsOn("lifecycleBeanPostProcessor")
    protected DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        return super.defaultAdvisorAutoProxyCreator();
    }

    @Bean
    protected AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        return super.authorizationAttributeSourceAdvisor(securityManager);
    }
}
```

- @Configuration 表示这是一个配置类，Spring 会将其作为配置类来加载，并为其中定义的 Bean 自动进行装配。它相当于传统的 XML 配置文件中的 <beans>。
- 用 @Bean 注解定义了两个 Bean ，Spring 启动时候会自动扫描并装配这两个 Bean ，也就是说，这里定义的两个 Bean 已经交给 Spring 容器管理了。
- 第一个 Bean 是 `DefaultAdvisorAutoProxyCreator` ，这是 Spring 框架中的一个类，它的作用是自动创建代理类。 @DependsOn("lifecycleBeanPostProcessor")：这个注解表示这个 Bean 的创建依赖于 lifecycleBeanPostProcessor，因为 lifecycleBeanPostProcessor 管理了 Shiro 中一些重要 Bean 的生命周期。
- 第二个 Bean 是 `AuthorizationAttributeSourceAdvisor`，这是 Shiro 自己实现的一个 AOP 切点类，这个类非常关键，它负责在运行时检查被调用的方法上是否带有权限注解。

`AuthorizationAttributeSourceAdvisor` 的关键源代码如下：

```java
public class AuthorizationAttributeSourceAdvisor extends StaticMethodMatcherPointcutAdvisor {

    private static final Class<? extends Annotation>[] AUTHZ_ANNOTATION_CLASSES =
            new Class[] {
                    RequiresPermissions.class, RequiresRoles.class,
                    RequiresUser.class, RequiresGuest.class, RequiresAuthentication.class
            };

    //这里很关键，在构造函数中直接 new 了一个切点，并调用 setAdvice 设置给了 Spring。
    public AuthorizationAttributeSourceAdvisor() {
        setAdvice(new AopAllianceAnnotationsAuthorizingMethodInterceptor());
    }

    //...

    //这里扫描指定的 Class 上是否存在身份验证注解。
    private boolean isAuthzAnnotationPresent(Class<?> targetClazz) {
        for( Class<? extends Annotation> annClass : AUTHZ_ANNOTATION_CLASSES ) {
            Annotation a = AnnotationUtils.findAnnotation(targetClazz, annClass);
            if ( a != null ) {
                return true;
            }
        }
        return false;
    }

    //...
}
```

整体上说， Shiro 自己实现了一个方法切点类（Method Pointcut Advisor），通过 @Configuration 和 @Bean 这两个注解，把它暴露给 Spring 去管理，而在切点类的构造方法中，直接设置了一个方法拦截器，也就是名字很长的 `AopAllianceAnnotationsAuthorizingMethodInterceptor`。在运行时，这个方法拦截器将会拦截所有带有权限注解的方法，先进行权限校验。

## 11.3 本章小结

TODO:完成这段内容
