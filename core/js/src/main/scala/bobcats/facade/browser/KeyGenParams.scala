package bobcats.facade.browser

import scala.scalajs.js
import bobcats.CipherAlgorithm
import java.lang

@js.native
private[bobcats] sealed trait KeyGenParams extends js.Any

@js.native
private[bobcats] sealed trait HmacKeyGenParams extends js.Any

private[bobcats] object HmacKeyGenParams {
  def apply(hash: String): HmacKeyGenParams =
    js.Dynamic
      .literal(
        name = "HMAC",
        hash = hash
      )
      .asInstanceOf[HmacKeyGenParams]
}

@js.native
private[bobcats] sealed trait AesKeyGenParams extends js.Any

private[bobcats] object AesKeyGenParams {
  def apply[A <: CipherAlgorithm](algorithm: A): AesKeyGenParams =
    js.Dynamic
      .literal(
        name = algorithm.toStringWebCrypto,
        length = algorithm.keyLength * lang.Byte.SIZE
      )
      .asInstanceOf[AesKeyGenParams]
}