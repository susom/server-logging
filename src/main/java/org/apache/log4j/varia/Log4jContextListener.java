/*
 * Copyright 2014 The Board of Trustees of The Leland Stanford Junior University.
 * All Rights Reserved.
 *
 * See the NOTICE and LICENSE files distributed with this work for information
 * regarding copyright ownership and licensing. You may not use this file except
 * in compliance with a written license agreement with Stanford University.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See your
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.log4j.varia;

import java.io.File;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;

/**
 * Listener to initialize Log4j when a web application is deployed, and shutdown
 * cleanly when it is undeployed.
 */
public class Log4jContextListener implements ServletContextListener {
  @Override
  public void contextInitialized(ServletContextEvent contextEvent) {
    ServletContext servletContext = contextEvent.getServletContext();
    String contextPath = servletContext.getContextPath();

    // Initialize logging if requested
    String log4jConfig = servletContext.getInitParameter("log4j.configuration");
    if (log4jConfig != null) {
      if (log4jConfig.contains("${context.path}")) {
        if (contextPath.length() == 0) {
          contextPath = "ROOT";
        } else {
          contextPath = contextPath.substring(1);
        }
        log4jConfig = log4jConfig.replaceAll("\\$\\{context.path\\}", contextPath);
      }

      try {
        log4jConfig = new File(log4jConfig).getAbsolutePath();
        DOMConfigurator.configure(log4jConfig);
      } catch (Exception e) {
        servletContext.log("Unable to configure log4j for " + contextPath + " using file: " + log4jConfig, e);
      }

      Logger log = Logger.getLogger(Log4jContextListener.class);
      log.info("Initialized log4j for " + contextPath + " using file: " + log4jConfig);
    } else {
      servletContext.log("Set servlet context parameter log4j.configuration to enable log4j for " + contextPath);
    }
  }

  @Override
  public void contextDestroyed(ServletContextEvent contextEvent) {
    ServletContext servletContext = contextEvent.getServletContext();
    String contextPath = servletContext.getContextPath();

    // Make sure locks on log files are released
    LogManager.shutdown();
    servletContext.log("Shutdown log4j for " + contextPath);
  }
}

