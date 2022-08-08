package bobcats.facade.browser

import scala.scalajs.js
import bobcats.CipherAlgorithm

@js.native
private[bobcats] sealed trait HmacImportParams extends js.Any

private[bobcats] object HmacImportParams {
  def apply(hash: String): HmacImportParams =
    js.Dynamic
      .literal(
        name = "HMAC",
        hash = hash
      )
      .asInstanceOf[HmacImportParams]
}

@js.native
private[bobcats] sealed trait AesImportParams extends js.Any

private[bobcats] object AesImportParams {
  def apply[A <: CipherAlgorithm](algorithm: A): AesImportParams =
    js.Dynamic.literal(name = algorithm.toStringWebCrypto).asInstanceOf[AesImportParams]
}
