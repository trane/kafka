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
