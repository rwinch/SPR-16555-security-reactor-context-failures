/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample;

import org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor;
import org.springframework.boot.web.reactive.context.AnnotationConfigReactiveWebApplicationContext;
import org.springframework.boot.web.reactive.context.ConfigurableReactiveWebApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.io.Closeable;
import java.io.IOException;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class SpringTestContext implements Closeable {
	private Object test;

	private ConfigurableReactiveWebApplicationContext context;


	public void setTest(Object test) {
		this.test = test;
	}

	@Override
	public void close() throws IOException {
		try {
			this.context.close();
		} catch(Exception e) {}
	}

	public SpringTestContext register(Class<?>... classes) {
		AnnotationConfigReactiveWebApplicationContext applicationContext = new AnnotationConfigReactiveWebApplicationContext();
		applicationContext.register(classes);
		this.context = applicationContext;
		return this;
	}

	public ConfigurableApplicationContext getContext() {
		if (!this.context.isRunning()) {
			this.context.refresh();
		}
		return this.context;
	}

	public void autowire() {
		this.context.refresh();

		AutowiredAnnotationBeanPostProcessor bpp = new AutowiredAnnotationBeanPostProcessor();
		bpp.setBeanFactory(this.context.getBeanFactory());
		bpp.processInjection(this.test);
	}
}
