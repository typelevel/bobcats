package bobcats.facade.node

import scala.scalajs.js
import scala.annotation.nowarn

@js.native
@nowarn("msg=never used")
private[bobcats] trait Decipher extends js.Any {
  def update(data: js.typedarray.Uint8Array): js.typedarray.Uint8Array = js.native
  def `final`(): js.typedarray.Uint8Array = js.native
  def setAutoPadding(autoPadding: Boolean): this.type = js.native
}