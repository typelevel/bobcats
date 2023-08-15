import cats.syntax.all._
import cats.parse.{Numbers, Parser => P}
import scodec.bits.ByteVector
import cats.data.NonEmptyList

object AESGCMEncryptTestVectorParser {

  import ResponseFileParser._

  case class TestVector(
      index: Int,
      key: ByteVector,
      iv: ByteVector,
      ad: ByteVector,
      plainText: ByteVector,
      cipherText: ByteVector,
    tag: ByteVector) {

    def show: String =
      s"""
        |Count = ${index}
        |Key = ${key.toHex}
        |IV = ${iv.toHex}
        |PT = ${plainText.toHex}
        |AAD = ${ad.toHex}
        |CT = ${cipherText.toHex}
        |Tag = ${tag.toHex}
      """.stripMargin
  }

  case class Section(testVectors: NonEmptyList[TestVector]) {
    def show: String = {
      val TestVector(_, key, iv, ad, pt, ct, tag) = testVectors.head
      s"""
         |[Keylen = ${key.length * 8}]
         |[IVlen = ${iv.length * 8}]
         |[PTlen = ${pt.length * 8}]
         |[AADlen = ${ad.length * 8}]
         |[Taglen = ${tag.length * 8}]
         |${testVectors.map(_.show).toList.mkString("\n")}
      """.stripMargin
    }
  }

  private val sectionHeader = 
    (sectionParam("Keylen", Numbers.digits.void) *> nl *>
      sectionParam("IVlen", Numbers.digits.void) *> nl *>
      sectionParam("PTlen", Numbers.digits.void) *> nl *>
      sectionParam("AADlen", Numbers.digits.void) *> nl *>
      sectionParam("Taglen", Numbers.digits.void))

  private val entry = (
    assignment("Count", Numbers.digits.map(_.toInt)) <* nl,
    assignment("Key", hexString) <* nl,
    assignment("IV", hexString) <* nl,
    assignment("PT", hexString) <* nl,
    assignment("AAD", hexString) <* nl,
    assignment("CT", hexString) <* nl,
    assignment("Tag", hexString)
  ).mapN(TestVector.apply)

  private val section =
    (sectionHeader *> entry.surroundedBy(whitespaces).rep).map {
      case entries => Section(entries)
    }.surroundedBy(whitespaces)

  val parser = header *> section.rep

}
