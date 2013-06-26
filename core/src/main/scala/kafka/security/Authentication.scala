/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package kafka.security

import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.SSLContext

object Authentication {

  private var initialized = false
  
  def initialize(config: SecurityConfig) {
    // If secure setup SSLContext
    synchronized {
        if (initialized) return
        initialized = true
	    val tms = config.truststorePwd match {
	      case pw: String =>
		    val ts = java.security.KeyStore.getInstance("JKS")
		    ts.load(new java.io.FileInputStream(config.truststore), pw.toCharArray)
		    val tmf = TrustManagerFactory.getInstance("SunX509")
		    tmf.init(ts)
		    tmf.getTrustManagers
	      case _ => null
	    }
	    val kms = config.keystorePwd match {
	      case pw: String =>
			val ks = java.security.KeyStore.getInstance("JKS")
			ks.load(new java.io.FileInputStream(config.keystore), pw.toCharArray)
			val kmf = KeyManagerFactory.getInstance("SunX509")
			kmf.init(ks, if (config.keyPwd != null) config.keyPwd.toCharArray else pw.toCharArray)
			kmf.getKeyManagers
	      case _ => null
	    }
	      
	    val sslContext = SSLContext.getInstance("TLS")
	    sslContext.init(kms, tms, null)
	    SSLContext.setDefault(sslContext)
    }
  }
}
