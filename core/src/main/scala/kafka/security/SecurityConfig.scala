package kafka.security

import kafka.utils.VerifiableProperties
import kafka.utils.Utils

class SecurityConfig(propFile: String) {
  
  val props = new VerifiableProperties(Utils.loadProps(propFile))
  
  /** Request client auth */
  val wantClientAuth = props.getBoolean("want.client.auth", false)

  /** Require client auth */
  val needClientAuth = props.getBoolean("need.client.auth", false)

  /** Keystore file location */
  val keystore = props.getString("keystore")
  
  /** Keystore file password */
  val keystorePwd = props.getString("keystorePwd")

  /** Keystore key password */
  val keyPwd = props.getString("keyPwd")
  
  /** Truststore file location */
  val truststore = props.getString("truststore")
  
  /** Truststore file password */
  val truststorePwd = props.getString("truststorePwd")
}
