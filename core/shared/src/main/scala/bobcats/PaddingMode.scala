package bobcats

sealed abstract class PaddingMode {
  private[bobcats] def toStringJava: String
  private[bobcats] def setAutoPaddingNodeJS: Boolean
}

object PaddingMode {
  case object None extends PaddingMode {
    private[bobcats] override def toStringJava: String = "NoPadding"
    private[bobcats] def setAutoPaddingNodeJS: Boolean = false
  }
  case object PKCS7 extends PaddingMode {
    // The JCA erroneously refers to PKCS#7 padding as PKCS#5
    private[bobcats] override def toStringJava: String = "PKCS5Padding"
    private[bobcats] def setAutoPaddingNodeJS: Boolean = true
  }
}
