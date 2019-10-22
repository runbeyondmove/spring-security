# HttpSecurity 
> A HttpSecurity is similar to Spring Security's XML <http> element in the namespace configuration. 
> It allows configuring web based security for specific http requests. 
> By default it will be applied to all requests, but can be restricted using requestMatcher(RequestMatcher) or other similar Methods.

翻译：HttpSecurity与Spring Security名称空间配置中的XML <http>元素相似。 
它允许为特定的http请求配置基于Web的安全性。 
默认情况下，它将应用于所有请求，但可以使用requestMatcher（RequestMatcher）或其他类似方法进行限制。

# AbstractConfiguredSecurityBuilder
> A base SecurityBuilder that allows SecurityConfigurer to be applied to it. 
> This makes modifying the SecurityBuilder a strategy that can be customized and broken up into a number of SecurityConfigurer objects 
> that have more specific goals than that of the SecurityBuilder.
> 
> For example, a SecurityBuilder may build an DelegatingFilterProxy, 
> but a SecurityConfigurer might populate the SecurityBuilder with the filters necessary for session management, form based login, authorization, etc.

翻译：SecurityBuilder的抽象实现类，允许将SecurityConfigurer应用于它。 
这使修改SecurityBuilder成为一种可以自定义的策略，并且可以细分为多个SecurityConfigurer对象，这些对象的目标比SecurityBuilder更为具体。
例如，SecurityBuilder可以构建DelegatingFilterProxy，但是SecurityConfigurer可以使用会话管理，基于表单的登录，授权等所需的过滤器填充SecurityBuilder。

引用文章：
> AbstractConfiguredSecurityBuilder是Spring Security Config对安全构建器SecurityBuilder的抽象基类实现。
> 它继承自安全构建器SecurityBuilder的另外一个抽象基类实现AbstractSecurityBuilder。
> 但不同的是,AbstractSecurityBuilder约定了SecurityBuilder构建的基本框架:最多被构建一次，
> 而AbstractConfiguredSecurityBuilder在此基础上做了如下扩展:
> 
> 1. 允许将多个安全配置器SecurityConfigurer应用到该SecurityBuilder上;
> 2. 定义了构建过程的生命周期(参考生命周期状态定义BuildState)；
> 3. 在生命周期基础之上实现并final了基类定义的抽象方法#doBuild，将构建划分为三个主要阶段#init,#configure,#performBuild;
> 对 #init/#configure阶段提供了实现;
> 对 #init/#configure阶段提供了前置回调#beforeInit/#beforeConfigure空方法供基类扩展;
> #performBuild定义为抽象方法要求子类提供实现；
> 4. 登记安全构建器工作过程中需要共享使用的一些对象。

相关源码（仔细分析）：
# AbstractConfiguredSecurityBuilder
```java
package org.springframework.security.config.annotation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.util.Assert;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * 源代码版本 : Spring Security Config 5.1.4.RELEASE
 * 
 * A base SecurityBuilder that allows SecurityConfigurer to be applied to
 * it. This makes modifying the SecurityBuilder a strategy that can be customized
 * and broken up into a number of SecurityConfigurer objects that have more
 * specific goals than that of the SecurityBuilder.
 * 
 *
 *
 * For example, a SecurityBuilder may build an DelegatingFilterProxy, but
 * a SecurityConfigurer might populate the SecurityBuilder with the
 * filters necessary for session management, form based login, authorization, etc.
 *
 * 源码分析原文链接：
 * [Spring Security Config : AbstractConfiguredSecurityBuilder](https://blog.csdn.net/andy_zhang2007/article/details/89913949)
 * 
 * @see WebSecurity
 *
 * @author Rob Winch
 *
 * @param <O> The object that this builder returns
 * @param <B> The type of this builder (that is returned by the base class)
 */
public abstract class AbstractConfiguredSecurityBuilder<O, B extends SecurityBuilder<O>>
		extends AbstractSecurityBuilder<O> {
	private final Log logger = LogFactory.getLog(getClass());

    // 所要应用到当前 SecurityBuilder 上的所有的 SecurityConfigurer
	private final LinkedHashMap<Class<? extends SecurityConfigurer<O, B>>, List<SecurityConfigurer<O, B>>> configurers 
            = new LinkedHashMap<Class<? extends SecurityConfigurer<O, B>>, List<SecurityConfigurer<O, B>>>();
	
    //  用于记录在初始化期间添加进来的 SecurityConfigurer       
	private final List<SecurityConfigurer<O, B>> configurersAddedInInitializing = 
			new ArrayList<SecurityConfigurer<O, B>>();

    // 共享对象
	private final Map<Class<? extends Object>, Object> sharedObjects = 
			new HashMap<Class<? extends Object>, Object>();

	private final boolean allowConfigurersOfSameType;

	private BuildState buildState = BuildState.UNBUILT;

    // 对象后置处理器，一般用于对象的初始化或者确保对象的销毁方法能够被调用到
	private ObjectPostProcessor<Object> objectPostProcessor;

	/***
	 * 构造函数
     * Creates a new instance with the provided ObjectPostProcessor. This post
	 * processor must support Object since there are many types of objects that may be
	 * post processed.
	 *
	 * @param objectPostProcessor the ObjectPostProcessor to use
	 */
	protected AbstractConfiguredSecurityBuilder(
			ObjectPostProcessor<Object> objectPostProcessor) {
		this(objectPostProcessor, false);
	}

	/***
	 *  构造函数
     * Creates a new instance with the provided ObjectPostProcessor. This post
	 * processor must support Object since there are many types of objects that may be
	 * post processed.
	 *
	 * @param objectPostProcessor the ObjectPostProcessor to use
	 * @param allowConfigurersOfSameType if true, will not override other
	 * SecurityConfigurer's when performing apply
	 */
	protected AbstractConfiguredSecurityBuilder(
			ObjectPostProcessor<Object> objectPostProcessor,
			boolean allowConfigurersOfSameType) {
		Assert.notNull(objectPostProcessor, "objectPostProcessor cannot be null");
		this.objectPostProcessor = objectPostProcessor;
		this.allowConfigurersOfSameType = allowConfigurersOfSameType;
	}

	/**
	 * Similar to #build() and #getObject() but checks the state to
	 * determine if #build() needs to be called first.
	 *
	 * @return the result of #build() or #getObject(). If an error occurs
	 * while building, returns null.
	 */
	public O getOrBuild() {
		if (isUnbuilt()) {
			try {
				return build();
			}
			catch (Exception e) {
				logger.debug("Failed to perform build. Returning null", e);
				return null;
			}
		}
		else {
			return getObject();
		}
	}

	/**
	 * Applies a SecurityConfigurerAdapter to this SecurityBuilder and
	 * invokes SecurityConfigurerAdapter#setBuilder(SecurityBuilder).
	 * 
	 * 应用一个 SecurityConfigurerAdapter 到该 SecurityBuilder，
     * SecurityConfigurerAdapter 是 SecurityConfigurer 接口的适配器实现
	 * @param configurer
	 * @return the SecurityConfigurerAdapter for further customizations
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurerAdapter<O, B>> C apply(C configurer)
			throws Exception {
		configurer.addObjectPostProcessor(objectPostProcessor);
		configurer.setBuilder((B) this);
		add(configurer);
		return configurer;
	}

	/**
	 * Applies a SecurityConfigurer to this SecurityBuilder overriding any
	 * SecurityConfigurer of the exact same class. Note that object hierarchies
	 * are not considered.
	 *
     * 应用一个 SecurityConfigurer 到该 SecurityBuilder 上
	 * @param configurer
	 * @return the SecurityConfigurerAdapter for further customizations
	 * @throws Exception
	 */
	public <C extends SecurityConfigurer<O, B>> C apply(C configurer) throws Exception {
		add(configurer);
		return configurer;
	}

	/**
	 * Sets an object that is shared by multiple SecurityConfigurer.
	 *
	 * @param sharedType the Class to key the shared object by.
	 * @param object the Object to store
	 */
	@SuppressWarnings("unchecked")
	public <C> void setSharedObject(Class<C> sharedType, C object) {
		this.sharedObjects.put(sharedType, object);
	}

	/**
	 * Gets a shared Object. Note that object heirarchies are not considered.
	 *
	 * @param sharedType the type of the shared Object
	 * @return the shared Object or null if it is not found
	 */
	@SuppressWarnings("unchecked")
	public <C> C getSharedObject(Class<C> sharedType) {
		return (C) this.sharedObjects.get(sharedType);
	}

	/**
	 * Gets the shared objects
	 * @return the shared Objects
	 */
	public Map<Class<? extends Object>, Object> getSharedObjects() {
		return Collections.unmodifiableMap(this.sharedObjects);
	}

	/**
	 * Adds SecurityConfigurer ensuring that it is allowed and invoking
	 * SecurityConfigurer#init(SecurityBuilder) immediately if necessary.
	 *
     * 添加 SecurityConfigurer 到当前 SecurityBuilder 上，添加过程做了同步处理
	 * @param configurer the SecurityConfigurer to add
	 * @throws Exception if an error occurs
	 */
	@SuppressWarnings("unchecked")
	private <C extends SecurityConfigurer<O, B>> void add(C configurer) throws Exception {
		Assert.notNull(configurer, "configurer cannot be null");

		Class<? extends SecurityConfigurer<O, B>> clazz 
				= (Class<? extends SecurityConfigurer<O, B>>) configurer.getClass();
		synchronized (configurers) {
			if (buildState.isConfigured()) {
				throw new IllegalStateException("Cannot apply " + configurer
						+ " to already built object");
			}
			List<SecurityConfigurer<O, B>> configs = allowConfigurersOfSameType ? this.configurers
					.get(clazz) : null;
			if (configs == null) {
				configs = new ArrayList<SecurityConfigurer<O, B>>(1);
			}
			configs.add(configurer);
			this.configurers.put(clazz, configs);
			if (buildState.isInitializing()) {
				this.configurersAddedInInitializing.add(configurer);
			}
		}
	}

	/**
	 * Gets all the SecurityConfigurer instances by its class name or an empty
	 * List if not found. Note that object hierarchies are not considered.
	 *
	 * @param clazz the SecurityConfigurer class to look for
	 * @return a list of SecurityConfigurers for further customization
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> List<C> getConfigurers(Class<C> clazz) {
		List<C> configs = (List<C>) this.configurers.get(clazz);
		if (configs == null) {
			return new ArrayList<>();
		}
		return new ArrayList<>(configs);
	}

	/**
	 * Removes all the SecurityConfigurer instances by its class name or an empty
	 * List if not found. Note that object hierarchies are not considered.
	 *
	 * @param clazz the SecurityConfigurer class to look for
	 * @return a list of SecurityConfigurers for further customization
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> List<C> removeConfigurers(Class<C> clazz) {
		List<C> configs = (List<C>) this.configurers.remove(clazz);
		if (configs == null) {
			return new ArrayList<>();
		}
		return new ArrayList<>(configs);
	}

	/**
	 * Gets the SecurityConfigurer by its class name or null if not
	 * found. Note that object hierarchies are not considered.
	 *
	 * @param clazz
	 * @return the SecurityConfigurer for further customizations
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> C getConfigurer(Class<C> clazz) {
		List<SecurityConfigurer<O, B>> configs = this.configurers.get(clazz);
		if (configs == null) {
			return null;
		}
		if (configs.size() != 1) {
			throw new IllegalStateException("Only one configurer expected for type "
					+ clazz + ", but got " + configs);
		}
		return (C) configs.get(0);
	}

	/**
	 * Removes and returns the SecurityConfigurer by its class name or
	 * null if not found. Note that object hierarchies are not considered.
	 *
	 * @param clazz
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> C removeConfigurer(Class<C> clazz) {
		List<SecurityConfigurer<O, B>> configs = this.configurers.remove(clazz);
		if (configs == null) {
			return null;
		}
		if (configs.size() != 1) {
			throw new IllegalStateException("Only one configurer expected for type "
					+ clazz + ", but got " + configs);
		}
		return (C) configs.get(0);
	}

	/**
	 * Specifies the ObjectPostProcessor to use.
	 * @param objectPostProcessor the ObjectPostProcessor to use. Cannot be null
	 * @return the SecurityBuilder for further customizations
	 */
	@SuppressWarnings("unchecked")
	public O objectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		Assert.notNull(objectPostProcessor, "objectPostProcessor cannot be null");
		this.objectPostProcessor = objectPostProcessor;
		return (O) this;
	}

	/**
	 * Performs post processing of an object. The default is to delegate to the
	 * ObjectPostProcessor.
	 *
	 * @param object the Object to post process
	 * @return the possibly modified Object to use
	 */
	protected <P> P postProcess(P object) {
		return this.objectPostProcessor.postProcess(object);
	}

	/**
	 *  对基类定义的 #doBuild 提供实现，并将其设置为 final， 该实现体现了
     * Spring Security Config 对 SecurityBuilder 构建过程生命周期的处理
     * Executes the build using the SecurityConfigurer's that have been applied
	 * using the following steps:
	 *
	 * 
	 * 1. Invokes #beforeInit() for any subclass to hook into
	 * 2. Invokes SecurityConfigurer#init(SecurityBuilder) for any
	 *  SecurityConfigurer that was applied to this builder.
	 * 3. Invokes #beforeConfigure() for any subclass to hook into
	 * 4.Invokes #performBuild() which actually builds the Object
	 * 
	 */
	@Override
	protected final O doBuild() throws Exception {
		synchronized (configurers) {
			buildState = BuildState.INITIALIZING;

			beforeInit();
			init();

			buildState = BuildState.CONFIGURING;

			beforeConfigure();
			configure();

			buildState = BuildState.BUILDING;

			O result = performBuild();

			buildState = BuildState.BUILT;

			return result;
		}
	}

	/**
	 *  留给子类扩展的生命周期方法
     * Invoked prior to invoking each SecurityConfigurer#init(SecurityBuilder)
	 * method. Subclasses may override this method to hook into the lifecycle without
	 * using a SecurityConfigurer.
	 */
	protected void beforeInit() throws Exception {
	}

	/**
	 *  留给子类扩展的生命周期方法
     * Invoked prior to invoking each
	 * SecurityConfigurer#configure(SecurityBuilder) method. Subclasses may
	 * override this method to hook into the lifecycle without using a
	 * SecurityConfigurer.
	 */
	protected void beforeConfigure() throws Exception {
	}

	/**
	 * 要求子类必须提供实现的构建过程方法
     * Subclasses must implement this method to build the object that is being returned.
	 *
	 * @return the Object to be buit or null if the implementation allows it
	 */
	protected abstract O performBuild() throws Exception;

    // 构建过程初始化方法 : 调用所有 SecurityConfigurer 的 #init 初始化方法
	@SuppressWarnings("unchecked")
	private void init() throws Exception {
		Collection<SecurityConfigurer<O, B>> configurers = getConfigurers();

		for (SecurityConfigurer<O, B> configurer : configurers) {
			configurer.init((B) this);
		}

		for (SecurityConfigurer<O, B> configurer : configurersAddedInInitializing) {
			configurer.init((B) this);
		}
	}

    // 构建过程配置方法 : 调用所有 SecurityConfigurer 的 #configure 配置方法
	@SuppressWarnings("unchecked")
	private void configure() throws Exception {
		Collection<SecurityConfigurer<O, B>> configurers = getConfigurers();

		for (SecurityConfigurer<O, B> configurer : configurers) {
			configurer.configure((B) this);
		}
	}

	private Collection<SecurityConfigurer<O, B>> getConfigurers() {
		List<SecurityConfigurer<O, B>> result = new ArrayList<SecurityConfigurer<O, B>>();
		for (List<SecurityConfigurer<O, B>> configs : this.configurers.values()) {
			result.addAll(configs);
		}
		return result;
	}

	/**
	 * Determines if the object is unbuilt.
	 * @return true, if unbuilt else false
	 */
	private boolean isUnbuilt() {
		synchronized (configurers) {
			return buildState == BuildState.UNBUILT;
		}
	}

	/**
	 * The build state for the application
     * 构建器构建过程生命周期定义
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	private static enum BuildState {
		/**
		 * This is the state before the Builder#build() is invoked
		 */
		UNBUILT(0),

		/**
		 * The state from when Builder#build() is first invoked until all the
		 * SecurityConfigurer#init(SecurityBuilder) methods have been invoked.
		 */
		INITIALIZING(1),

		/**
		 * The state from after all SecurityConfigurer#init(SecurityBuilder) have
		 * been invoked until after all the
		 * SecurityConfigurer#configure(SecurityBuilder) methods have been
		 * invoked.
		 */
		CONFIGURING(2),

		/**
		 * From the point after all the
		 * SecurityConfigurer#configure(SecurityBuilder) have completed to just
		 * after AbstractConfiguredSecurityBuilder#performBuild().
		 */
		BUILDING(3),

		/**
		 * After the object has been completely built.
		 */
		BUILT(4);

		private final int order;

		BuildState(int order) {
			this.order = order;
		}

		public boolean isInitializing() {
			return INITIALIZING.order == order;
		}

		/**
		 * Determines if the state is CONFIGURING or later
		 * @return
		 */
		public boolean isConfigured() {
			return order >= CONFIGURING.order;
		}
	}
}
```

# HttpSecurity
```java
public final class HttpSecurity extends
		AbstractConfiguredSecurityBuilder<DefaultSecurityFilterChain, HttpSecurity>
		implements SecurityBuilder<DefaultSecurityFilterChain>,
		HttpSecurityBuilder<HttpSecurity> {
	private final RequestMatcherConfigurer requestMatcherConfigurer;
	private List<Filter> filters = new ArrayList<>();
	private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;
	private FilterComparator comparator = new FilterComparator();

	public FormLoginConfigurer<HttpSecurity> formLogin() throws Exception {
		return getOrApply(new FormLoginConfigurer<>());
	}
	
	public ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests()
			throws Exception {
		ApplicationContext context = getContext();
		return getOrApply(new ExpressionUrlAuthorizationConfigurer<>(context))
				.getRegistry();
	}
	
    // ...省略
}
```

查看两者的源码，可以发现以下：
1. HttpSecurity是抽象类AbstractConfiguredSecurityBuilder的实现类
2. 方法`public <C extends SecurityConfigurerAdapter<O, B>> C apply(C configurer)throws Exception {}`中
这里的C对应的泛型就是SecurityConfigurerAdapter<O, B>,而O,B对应到HttpSecurity的声明就是<DefaultSecurityFilterChain, HttpSecurity>

HttpSecurity.apply 返回一个SecurityConfigurerAdapter<O, B>，所以这里只要继承该类，就是apply需要的对象了

如下示例
```java
/**
 * 验证码配置
 * @author : zhuqiang
 * @version : V1.0
 * @date : 2018/8/5 20:05
 */
@Component
public class ValidateCodeSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    /**
     * @see validateCodeFilter  目前融合了短信和图形验证码的验证功能
     */
    @Autowired
    private Filter validateCodeFilter;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // 由源码得知，在最前面的是UsernamePasswordAuthenticationFilter
        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
```

