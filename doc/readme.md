# 项目结构
- spring-security # 根目录
    - security-app # app相关特定代码
    - spring-browser # 浏览器完全特定代码
    - spring-core # 核心业务逻辑
    - security-demo # 用来写例子，最开始的restfull相关的几节课程都是在该项目中编写讲解的；引用core的依赖配置
依赖关系为： demo 依赖 browser和app,browser和app 依赖core