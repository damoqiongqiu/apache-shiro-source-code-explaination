## Apache Shiro 源码解析

Apache Shiro 是一个轻量级的 Java 安全框架，也是 Apache 基金会的顶级开源项目之一。 Shiro 提供了认证（Authentication）、授权（Authorization）、会话管理（Session Management）、缓存（Caching）以及加密（Cryptography）等功能，涵盖了应用安全的各个重要方面。

经过 20 多年的发展，Shiro 已经被广泛应用在各种业务系统中。Shiro 的架构非常灵活，它既可以脱离 Web 容器独立运行，也能与 Spring 无缝集成。在过去的十多年中， Shiro 一直是最流行的 Java 安全框架之一。

虽然当前市面上已经出现了 `SpringSecurity` 这样的竞争者，但是从阅读源代码的角度看， Shiro 框架依然具有自己独特的优势。首先它的架构非常简洁，与其它的开源组件不存在复杂的依赖关系。其次，经过多年的不断优化， Shiro 的代码和注释质量非常高。所以， Shiro 不仅是一个实用的安全框架，也是一份珍贵的学习资源。在这本书中，我们将会详细分析 Shiro 的架构和源代码，开发者可以充分理解安全领域的关键概念，在使用其它安全框架时也会更加得心应手。

## 资源链接

- Apache Shiro 在 github 上的官方仓库： https://github.com/apache/shiro
- Apache Shiro 官方网站：https://shiro.apache.org/
- 本书实例项目：https://gitee.com/mumu-osc/nicefish-spring-boot
- 本书文字稿：https://gitee.com/mumu-osc/apache-shiro-source-code-explaination

## 版权声明

本书基于 [**CC BY-NC-ND 4.0 许可协议**](https://creativecommons.org/licenses/by-nc-nd/4.0/deed.en)发布，自由转载-非商用-非衍生-保持署名。

**版权归大漠穷秋所有 © 2024 ，侵权必究。**
